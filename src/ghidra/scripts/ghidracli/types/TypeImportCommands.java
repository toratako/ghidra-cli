package ghidracli.types;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.CParserConstants;
import ghidra.app.util.cparser.C.Declaration;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.cparser.C.Token;
import ghidra.app.util.cparser.C.TokenMgrError;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidracli.session.ProgramSession;
import java.io.StringReader;
import java.math.BigInteger;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class TypeImportCommands {
  private final ProgramSession session;

  public TypeImportCommands(ProgramSession session) {
    this.session = session;
  }

  public JsonObject handleTypeImportC(JsonObject args) {
    if (session.program() == null) return errorResult("No program loaded");

    String code = getArgString(args, "code");
    if (code == null || code.trim().isEmpty()) {
      return errorResult("C code required");
    }

    String categoryPath = getArgString(args, "category");

    DataTypeManager dtm = session.program().getDataTypeManager();
    try (ImportTypes parsedManager = new ImportTypes(dtm)) {

      String processedCode = code.trim();
      if (!processedCode.endsWith(";")) {
        processedCode += ";";
      }

      // Parse without changing the Program, retaining existing references'
      // source identities until the definitions are staged and relocated.
      CParser parser = new CParser(parsedManager, false, new DataTypeManager[] {dtm});
      parser.setMonitor(session.monitor());
      parsedManager.parse(parser, processedCode);
      String parseMessages = parser.getParseMessages();

      Set<String> definedNames = new HashSet<>();
      definedNames.addAll(parser.getComposites().keySet());
      definedNames.addAll(parser.getEnums().keySet());
      definedNames.addAll(parser.getTypes().keySet());
      definedNames.addAll(parser.getFunctions().keySet());

      Set<DataType> parsedTypes = Collections.newSetFromMap(new IdentityHashMap<>());
      parsedTypes.addAll(parser.getComposites().values());
      parsedTypes.addAll(parser.getEnums().values());
      parsedTypes.addAll(parser.getTypes().values());
      parsedTypes.addAll(parser.getFunctions().values());

      // C tag and typedef namespaces can name distinct definitions at the
      // same Ghidra path. Resolving either with replacement would discard
      // the other and redirect its users to a different kind of type.
      Map<String, DataType> definitionsByPath = new HashMap<>();
      for (DataType type : parsedTypes) {
        if (definitionsByPath.putIfAbsent(type.getPathName(), type) != null) {
          throw new IllegalArgumentException(
              "C definitions conflict at the same type path: " + type.getPathName());
        }
      }
      // CParser can keep an earlier declaration in a field after replacing
      // the same path in its definition maps. Traverse object identities
      // before any native resolve can collapse those different definitions.
      List<DataType> dependencies = TypeArchiveGraph.dependencies(parsedTypes, session.monitor());
      verifyLayouts(dependencies);
      verifyDeclaredBitFields(dependencies, parsedTypes);

      CategoryPath lookupPath = CategoryPath.ROOT;
      if (categoryPath != null) {
        String normalizedPath = categoryPath.startsWith("/") ? categoryPath : "/" + categoryPath;
        TypeResolver.requirePathDepth(normalizedPath);
        lookupPath = new CategoryPath(normalizedPath);
      }
      Map<String, CategoryPath> definitionPaths = new HashMap<>();
      Set<String> visiblePaths = new HashSet<>();
      for (DataType dt : parsedTypes) {
        if (isUserFacingDataType(dt)) visiblePaths.add(dt.getPathName());
      }
      for (DataType contained : dependencies) {
        session.monitor().checkCancelled();
        if (!isDefinition(contained)) continue;
        boolean declared =
            parsedTypes.contains(contained)
                || contained.getSourceArchive() == null
                || (contained instanceof FunctionDefinition
                    && definedNames.contains(contained.getName()));
        if (!declared) continue;
        // Existing references may share this path before the imported
        // declarations move to their requested destination category.
        DataType previous = definitionsByPath.putIfAbsent(contained.getPathName(), contained);
        if (previous != null && previous != contained)
          TypeArchiveGraph.requireEquivalent(contained, previous, session.monitor());
        CategoryPath destination = contained.getCategoryPath();
        if (categoryPath != null) {
          destination =
              isUserFacingDataType(contained)
                  ? lookupPath
                  : new CategoryPath(lookupPath, "functions");
        }
        definitionPaths.put(contained.getPathName(), destination);
      }

      Set<DataType> stagedTypes = new HashSet<>();
      Set<DataType> visibleTypes = new HashSet<>();
      Set<String> importedPaths = new HashSet<>();
      // Only the temporary manager needs a transaction here; ProgramSession
      // continues to own the live Program transaction and saving.
      int stagingTransaction = parsedManager.startTransaction("Stage C definitions");
      try {
        DataTypeConflictHandler stagingHandler =
            new DataTypeConflictHandler() {
              @Override
              public ConflictResult resolveConflict(DataType added, DataType existing) {
                return added.getSourceArchive() == null
                    ? ConflictResult.REPLACE_EXISTING
                    : ConflictResult.USE_EXISTING;
              }

              @Override
              public boolean shouldUpdate(DataType source, DataType local) {
                return source.getSourceArchive() == null;
              }

              @Override
              public DataTypeConflictHandler getSubsequentHandler() {
                return this;
              }
            };
        for (DataType dt : parsedTypes) {
          session.monitor().checkCancelled();
          parsedManager.resolve(dt, stagingHandler);
        }
        // Resolve the entire graph before relocation. Equivalent typedefs
        // can reference live definitions, and anonymous members are absent
        // from the parser's definition maps.
        Map<DataType, CategoryPath> destinations = new HashMap<>();
        for (Map.Entry<String, CategoryPath> entry : definitionPaths.entrySet()) {
          DataType staged = parsedManager.getDataType(entry.getKey());
          if (staged == null) {
            throw new IllegalStateException("C definition was not staged: " + entry.getKey());
          }
          destinations.put(staged, entry.getValue());
        }
        for (Map.Entry<DataType, CategoryPath> entry : destinations.entrySet()) {
          DataType staged = entry.getKey();
          parsedManager.disassociate(staged);
          String name = staged.getName();
          parsedManager
              .createCategory(entry.getValue())
              .moveDataType(staged, DataTypeConflictHandler.REPLACE_HANDLER);
          importedPaths.add(parsedManager.getDataType(entry.getValue(), name).getPathName());
        }
        for (DataType dt : parsedTypes) {
          CategoryPath path = definitionPaths.getOrDefault(dt.getPathName(), dt.getCategoryPath());
          DataType staged = parsedManager.getDataType(path, dt.getName());
          if (staged == null) {
            throw new IllegalStateException("C definition missing after staging: " + dt.getName());
          }
          stagedTypes.add(staged);
          if (visiblePaths.contains(dt.getPathName())) visibleTypes.add(staged);
        }
      } finally {
        parsedManager.endTransaction(stagingTransaction, true);
      }

      // Referenced types outside this import retain their live definitions,
      // even if staging a declaration affected a shared dependency there.
      DataTypeConflictHandler handler =
          new DataTypeConflictHandler() {
            @Override
            public ConflictResult resolveConflict(DataType added, DataType existing) {
              return importedPaths.contains(added.getPathName())
                  ? ConflictResult.REPLACE_EXISTING
                  : ConflictResult.USE_EXISTING;
            }

            @Override
            public boolean shouldUpdate(DataType source, DataType local) {
              return importedPaths.contains(source.getPathName());
            }

            @Override
            public DataTypeConflictHandler getSubsequentHandler() {
              return this;
            }
          };
      Set<DataType> replaced = new HashSet<>();
      for (String path : importedPaths) {
        DataType existing = dtm.getDataType(path);
        if (existing != null) replaced.add(existing);
      }
      // Replacement declarations intentionally change these definitions,
      // but native size propagation must still preserve their existing
      // parents, complete listing applications, and neighboring code units.
      TypeResizeCommands.PropagationSnapshot propagation =
          replaced.isEmpty() ? null : new TypeResizeCommands.PropagationSnapshot(session, replaced);
      Set<DataType> importedTypes = new HashSet<>();
      Set<DataType> resolvedTypes = new HashSet<>();
      for (DataType dt : stagedTypes) {
        session.monitor().checkCancelled();
        DataType imported = dtm.resolve(dt, handler);
        resolvedTypes.add(imported);
        if (visibleTypes.contains(dt)) importedTypes.add(imported);
      }
      verifyLayouts(TypeArchiveGraph.dependencies(resolvedTypes, session.monitor()));
      if (propagation != null) propagation.verifyReplacements();

      JsonArray typesArray = new JsonArray();
      for (String name : definedNames) {
        DataType best = findBestParsedDataType(name, importedTypes, lookupPath);
        if (best != null) {
          JsonObject typeInfo = new JsonObject();
          typeInfo.addProperty("name", best.getName());
          typeInfo.addProperty("path", best.getPathName());
          typeInfo.addProperty("size", best.getLength());
          typeInfo.addProperty("category", best.getCategoryPath().toString());
          typesArray.add(typeInfo);
        }
      }

      JsonObject response = new JsonObject();
      response.addProperty("status", "imported");
      response.add("types", typesArray);
      if (parseMessages != null && !parseMessages.trim().isEmpty()) {
        response.addProperty("messages", parseMessages.trim());
      }
      return response;
    } catch (ParseException | TokenMgrError failure) {
      return errorResult("C parse error: " + failure.getMessage());
    } catch (Exception e) {
      return errorResult("Failed to import C types: " + e.getMessage(), e);
    }
  }

  /** Native parsing can return normally after omitting requested definitions or members. */
  private static void requireCompleteParse(String messages) {
    if (messages == null) return;
    for (String line : messages.lines().toList()) {
      if (line.startsWith("Bad structure size ") || line.startsWith("BAD data type struct size "))
        throw new IllegalArgumentException("C parser discarded a field: " + messages.trim());
      if (line.startsWith("duplicate enum value: ")
          || line.startsWith("Parent structure ")
          || line.startsWith("Problem with type ")
          || line.startsWith("Problem adding DataType "))
        throw new IllegalArgumentException(
            "C parser discarded a definition or member: " + messages.trim());
    }
  }

  /** Keep CParser's external lookups exact without replacing its local declarations. */
  private final class ImportTypes extends StandAloneDataTypeManager {
    private final TypeResolver resolver = new TypeResolver(session);
    private TagDeclarations tags;
    private CParser parser;
    private RuntimeException lookupFailure;

    ImportTypes(DataTypeManager programTypes) {
      super("C import", programTypes.getDataOrganization());
    }

    void parse(CParser parser, String code) throws ParseException, CancelledException {
      tags = tagDeclarations(code, session.monitor());
      this.parser = parser;
      try {
        parser.parse(code);
        requireCompleteParse(parser.getParseMessages());
        try (ImportTypes evaluated = new ImportTypes(session.program().getDataTypeManager())) {
          evaluated.tags = tags;
          CParser expressions = new CParser(evaluated, false, null);
          evaluated.parser = expressions;
          expressions.setMonitor(session.monitor());
          cloneTypes(parser.getTypes(), expressions.getTypes(), evaluated);
          cloneTypes(parser.getComposites(), expressions.getComposites(), evaluated);
          cloneTypes(parser.getEnums(), expressions.getEnums(), evaluated);
          cloneTypes(parser.getFunctions(), expressions.getFunctions(), evaluated);
          // A later definition can make sizeof evaluate differently from the
          // original parse. Compare native output before trusting reevaluation.
          expressions.parse(code);
          requireCompleteParse(expressions.getParseMessages());
          verifyParsedDefinitions(parser.getTypes(), expressions.getTypes());
          verifyParsedDefinitions(parser.getComposites(), expressions.getComposites());
          verifyParsedDefinitions(parser.getEnums(), expressions.getEnums());
          verifyParsedDefinitions(parser.getFunctions(), expressions.getFunctions());
          verifyConstantExpressions(expressions, code);
          requireCompleteParse(expressions.getParseMessages());
        }
      } catch (ParseException failure) {
        // Native CParser wraps runtime lookup failures without retaining
        // their message or cause. Preserve the ambiguity candidates.
        if (lookupFailure != null) throw lookupFailure;
        throw failure;
      } finally {
        this.parser = null;
      }
    }

    private void verifyParsedDefinitions(Map<String, DataType> source, Map<String, DataType> parsed)
        throws CancelledException {
      for (var entry : source.entrySet()) {
        session.monitor().checkCancelled();
        DataType reevaluated = parsed.get(entry.getKey());
        if (reevaluated == null)
          throw new IllegalArgumentException(
              "C parser lost definition: " + entry.getValue().getPathName());
        try {
          TypeArchiveGraph.requireEquivalent(entry.getValue(), reevaluated, session.monitor());
        } catch (IllegalArgumentException failure) {
          throw new IllegalArgumentException(
              "C parser produced inconsistent definition at " + entry.getValue().getPathName(),
              failure);
        }
      }
    }

    private void cloneTypes(
        Map<String, DataType> source, Map<String, DataType> target, DataTypeManager manager)
        throws CancelledException {
      for (var entry : source.entrySet()) {
        session.monitor().checkCancelled();
        target.put(entry.getKey(), entry.getValue().clone(manager));
      }
    }

    private void verifyConstantExpressions(CParser parser, String code)
        throws ParseException, CancelledException {
      // Keep a separate lexical cursor so declarations nested in sizeof
      // are checked even when evaluating an outer expression consumes them.
      // The isolated type maps keep those evaluations out of the import.
      CParser tokens = new CParser(new StringReader(code));
      Token first = tokens.getToken(0);
      while (tokens.getNextToken().kind != CParserConstants.EOF) {
        session.monitor().checkCancelled();
      }
      Token previous = first;
      Token token = first.next;
      SignatureTypes.DeclaratorScan declarators = new SignatureTypes.DeclaratorScan();
      Token resumeDeclarators = null;
      while (token.kind != CParserConstants.EOF) {
        session.monitor().checkCancelled();
        if (token == resumeDeclarators) resumeDeclarators = null;
        boolean declarationToken = resumeDeclarators == null;
        if (token.kind == CParserConstants.ATTRIBUTE
            || token.kind == CParserConstants.DECLSPEC
            || token.kind == CParserConstants.READABLETO
            || token.kind == CParserConstants.ALIGNAS
            || token.kind == CParserConstants.ASM
            || "[".equals(token.image) && "[".equals(token.next.image)) {
          parseAt(parser, token);
          parser.DeclSpec(new Declaration());
          token = parser.getToken(0).next;
          continue;
        }
        if ("{".equals(token.image) && ")".equals(previous.image)) {
          parseAt(parser, token);
          parser.CompoundStatement();
          previous = parser.getToken(0);
          token = previous.next;
          declarators.reset();
          continue;
        }
        if (declarationToken) declarators.check(token);
        previous = token;
        token = token.next;
        if (declarationToken && ("=".equals(previous.image) || ":".equals(previous.image))) {
          parseAt(parser, token);
          if ("=".equals(previous.image)) parser.Initializer();
          else parser.ConstantExpression();
          resumeDeclarators = parser.getToken(0).next;
        }
        if ("[".equals(previous.image) && !"]".equals(token.image)) {
          parseAt(parser, token);
          long length = constantInteger(parser, "array length", previous);
          if (declarationToken) resumeDeclarators = parser.getToken(0).next;
          if (length < 0 || length > Integer.MAX_VALUE)
            throw new IllegalArgumentException("Array length exceeds its supported range");
        }
        if (previous.kind != CParserConstants.ENUM) continue;
        parseAt(parser, token);
        Token next = parser.getToken(1);
        while (next.kind == CParserConstants.ATTRIBUTE
            || next.kind == CParserConstants.ALIGNAS
            || next.kind == CParserConstants.ASM
            || "[".equals(next.image) && "[".equals(parser.getToken(2).image)) {
          parser.DeclSpec(new Declaration());
          next = parser.getToken(1);
        }
        if (next.kind == CParserConstants.IDENTIFIER) parser.getNextToken();
        if (!"{".equals(parser.getToken(1).image)) continue;
        parser.getNextToken();
        long nextValue = 0;
        while (!"}".equals(parser.getToken(1).image)) {
          session.monitor().checkCancelled();
          next = parser.getToken(1);
          if (next.kind == CParserConstants.LINE || next.kind == CParserConstants.LINEALT) {
            parser.LineDef();
            continue;
          }
          if (next.kind == CParserConstants.PRAGMA || next.kind == CParserConstants.PRAGMA_FUNC) {
            parser.PragmaSpec();
            continue;
          }
          if (next.kind == CParserConstants.STATICASSERT) {
            parser.StaticAssert();
            continue;
          }
          Token member = parser.getNextToken();
          long value = nextValue;
          if ("=".equals(parser.getToken(1).image)) {
            parser.getNextToken();
            value = constantInteger(parser, "enum value", member);
          }
          // Native Enumerator narrows explicit values to int and increments
          // subsequent members in int arithmetic, without a parse diagnostic.
          if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE)
            throw new IllegalArgumentException("C parser enum value exceeds its supported range");
          nextValue = value + 1;
          if (",".equals(parser.getToken(1).image)) parser.getNextToken();
        }
      }
    }

    private void parseAt(CParser parser, Token next) {
      parser.ReInit(new StringReader(""));
      // ReInit clears native lookahead; the recorded token chain supplies the
      // expression while retaining its original source positions.
      parser.getToken(0).next = next;
    }

    private long constantInteger(CParser parser, String subject, Token token)
        throws ParseException, CancelledException {
      Token before = parser.getToken(0);
      Object value = parser.ConstantExpression();
      Token after = parser.getToken(0).next;
      for (Token literal = before.next; literal != after; literal = literal.next) {
        session.monitor().checkCancelled();
        if (literal.kind != CParserConstants.INTEGER_LITERAL) continue;
        String number =
            literal
                .image
                .replaceFirst("(?i)i(?:8|16|32|64)$", "")
                .replaceFirst("(?i)(?:ull|ll|ul|l|u)$", "");
        BigInteger magnitude =
            number.startsWith("0x") || number.startsWith("0X")
                ? new BigInteger(number.substring(2), 16)
                : new BigInteger(number);
        // Native Constant truncates to long before returning the expression.
        // A wrapped literal can otherwise look like an exact small value.
        if (magnitude.bitLength() > 63)
          throw new IllegalArgumentException(
              "C parser cannot preserve "
                  + subject
                  + ": integer literal exceeds its supported range");
      }
      if (value instanceof Long number) return number;
      if (value instanceof Integer number) return number;
      if (value instanceof Character character) return character;
      throw new IllegalArgumentException(
          "C parser could not evaluate "
              + subject
              + " at line "
              + token.beginLine
              + ", column "
              + token.beginColumn);
    }

    @Override
    public void findDataTypes(String name, List<DataType> results) {
      super.findDataTypes(name, results);
      if (parser == null
          || !results.isEmpty()
          || !name.matches("[A-Za-z_$][A-Za-z_$0-9]*")
          || tags.defined.contains(name)) return;
      Token previous = parser.getToken(0);
      Token next = parser.getToken(1);
      // Native parsing probes a field/parameter/typedef name after its type.
      if (previous.kind == CParserConstants.IDENTIFIER
          && name.equals(next.image)
          && !name.equals(previous.image)) return;
      try {
        DataType existing = resolver.resolveRegisteredDataType(name);
        if (existing != null) {
          Integer kind = tags.kinds.get(name);
          if (kind != null
              && !(kind == CParserConstants.STRUCT && existing instanceof Structure)
              && !(kind == CParserConstants.UNION && existing instanceof Union)
              && !(kind == CParserConstants.ENUM
                  && existing instanceof ghidra.program.model.data.Enum))
            throw new IllegalArgumentException(
                "C tag kind does not match registered type: " + existing.getPathName());
          results.add(existing.clone(this));
        }
      } catch (RuntimeException failure) {
        lookupFailure = failure;
        throw failure;
      }
    }
  }

  private static final class TagDeclarations {
    final Set<String> defined = new HashSet<>();
    final Map<String, Integer> kinds = new HashMap<>();
  }

  /** Tag bodies shadow external names throughout their declaration, including forward uses. */
  private static TagDeclarations tagDeclarations(String code, TaskMonitor monitor)
      throws CancelledException {
    TagDeclarations tags = new TagDeclarations();
    CParser tokens = new CParser(new StringReader(code));
    for (Token token = tokens.getNextToken();
        token.kind != CParserConstants.EOF;
        token = tokens.getNextToken()) {
      monitor.checkCancelled();
      requireLosslessFloating(tokens, token);
      if (token.kind != CParserConstants.STRUCT
          && token.kind != CParserConstants.UNION
          && token.kind != CParserConstants.ENUM) continue;
      int kind = token.kind;
      token = tokens.getNextToken();
      // Attributes and declspecs may precede the tag name. Ignore their
      // balanced arguments so identifiers there cannot become tag names.
      while (token.kind != CParserConstants.IDENTIFIER
          && token.kind != CParserConstants.EOF
          && !"{".equals(token.image)
          && !";".equals(token.image)) {
        monitor.checkCancelled();
        if ("(".equals(token.image)) {
          int depth = 1;
          while (depth > 0) {
            monitor.checkCancelled();
            token = tokens.getNextToken();
            if (token.kind == CParserConstants.EOF) return tags;
            if ("(".equals(token.image)) depth++;
            if (")".equals(token.image)) depth--;
          }
        }
        token = tokens.getNextToken();
      }
      if (token.kind != CParserConstants.IDENTIFIER) continue;
      String name = token.image;
      Integer previousKind = tags.kinds.putIfAbsent(name, kind);
      if (previousKind != null && previousKind != kind)
        throw new IllegalArgumentException("C tag name has conflicting kinds: " + name);
      token = tokens.getNextToken();
      // Native CParser accepts a parent struct or an enum's underlying
      // type after ':'. Neither is another definition's tag name.
      if (":".equals(token.image)) {
        do {
          monitor.checkCancelled();
          token = tokens.getNextToken();
          requireLosslessFloating(tokens, token);
        } while (token.kind != CParserConstants.EOF
            && !"{".equals(token.image)
            && !";".equals(token.image)
            && !",".equals(token.image)
            && !")".equals(token.image));
      }
      if ("{".equals(token.image)) tags.defined.add(name);
      if (token.kind == CParserConstants.EOF) break;
    }
    return tags;
  }

  private static void requireLosslessFloating(CParser tokens, Token token) {
    Token next = SignatureTypes.lossyFloatingSpecifier(tokens, token);
    if (next != null)
      throw new IllegalArgumentException(
          "Unsupported C floating-point specifiers: "
              + token.image
              + " "
              + next.image
              + "; Ghidra's C parser converts them to double. Use an exact registered type name instead");
  }

  private void verifyLayouts(Iterable<DataType> types) throws CancelledException {
    for (DataType type : types) {
      session.monitor().checkCancelled();
      if (type instanceof Structure) TypeFields.verifyComponentCount((Structure) type);
      else if (type instanceof Composite) TypeFields.verifySize((Composite) type);
      else if (type instanceof Array) {
        Array array = (Array) type;
        long length = (long) array.getNumElements() * array.getElementLength();
        if (length > Integer.MAX_VALUE
            || length < 0
            || !array.isZeroLength() && array.getLength() != length)
          throw new IllegalArgumentException(
              "Array size exceeds its supported range in " + type.getPathName());
      }
    }
  }

  private void verifyDeclaredBitFields(Iterable<DataType> types, Set<DataType> declared)
      throws CancelledException {
    for (DataType type : types) {
      session.monitor().checkCancelled();
      // Referencing a stored definition does not request new field widths.
      // Explicit tag bodies may reuse an equivalent stored definition;
      // anonymous/new composites retain no source archive before staging.
      if (!(type instanceof Composite)
          || type.getSourceArchive() != null && !declared.contains(type)) continue;
      for (DataTypeComponent field : ((Composite) type).getDefinedComponents()) {
        session.monitor().checkCancelled();
        if (field.getDataType() instanceof BitFieldDataType bits
            && bits.getDeclaredBitSize() != bits.getBitSize())
          throw new IllegalArgumentException(
              "Bit-field width exceeds the base type; clipping is not allowed in "
                  + type.getPathName());
      }
    }
  }

  private boolean isDefinition(DataType dt) {
    return dt instanceof Composite
        || dt instanceof ghidra.program.model.data.Enum
        || dt instanceof TypeDef
        || dt instanceof FunctionDefinition;
  }

  private boolean isUserFacingDataType(DataType dt) {
    if (dt == null) return false;
    // CParser also exposes the function definitions backing typedefs. They
    // belong under functions even when reached through a contained type
    // rather than the parser's function map.
    return !(dt instanceof FunctionDefinition);
  }

  private DataType findBestParsedDataType(
      String name, Set<DataType> parsed, CategoryPath preferred) {
    DataType best = null;
    for (DataType dt : parsed) {
      if (!dt.getName().equals(name)) continue;
      if (dt.getCategoryPath().equals(preferred)) {
        return dt;
      }
      if (best == null) best = dt;
    }
    return best;
  }
}
