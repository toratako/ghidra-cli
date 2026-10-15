public class CheckAddressCodec extends ghidra.app.script.GhidraScript {
  private void require(boolean value, String message) {
    if (!value) throw new IllegalStateException(message);
  }

  private void roundtrip(
      ghidra.program.model.address.AddressFactory factory,
      ghidra.program.model.address.Address address) {
    String text = AddressCodec.format(address);
    var parsed = AddressCodec.parseCanonical(factory, text);
    require(address.equals(parsed), "Address roundtrip failed: " + text);
    require(
        address.getAddressSpace().equals(parsed.getAddressSpace()), "Lost address space: " + text);
    require(address.getOffset() == parsed.getOffset(), "Lost byte offset: " + text);
    require(
        address.getAddressableWordOffset() == parsed.getAddressableWordOffset(),
        "Lost word offset: " + text);
  }

  public void run() throws Exception {
    var ram =
        new ghidra.program.model.address.GenericAddressSpace(
            "ram", 64, ghidra.program.model.address.AddressSpace.TYPE_RAM, 0);
    var word =
        new ghidra.program.model.address.GenericAddressSpace(
            "word", 24, 2, ghidra.program.model.address.AddressSpace.TYPE_RAM, 1);
    word.setShowSpaceName(true);
    var wide =
        new ghidra.program.model.address.GenericAddressSpace(
            "wide", 63, 2, ghidra.program.model.address.AddressSpace.TYPE_RAM, 3);
    wide.setShowSpaceName(true);
    var signedWord =
        new ghidra.program.model.address.GenericAddressSpace(
            "signed_word", 63, 2, ghidra.program.model.address.AddressSpace.TYPE_CONSTANT, 4);
    var factory =
        new ghidra.program.model.address.DefaultAddressFactory(
            new ghidra.program.model.address.AddressSpace[] {ram, word, wide, signedWord}, ram);
    for (long offset : new long[] {0, 0x401000, Long.MIN_VALUE, -1L}) {
      roundtrip(factory, ram.getAddress(offset));
    }
    for (long offset : new long[] {0x2000, 0x2001, 0x1ffffff}) {
      roundtrip(factory, word.getAddress(offset));
    }
    for (long offset : new long[] {Long.MIN_VALUE, -1L})
      roundtrip(factory, wide.getAddress(offset));
    for (long offset : new long[] {Long.MIN_VALUE, -3, -1, 1, Long.MAX_VALUE}) {
      roundtrip(factory, signedWord.getAddress(offset));
    }

    var picLanguage =
        ghidra.program.util.DefaultLanguageService.getLanguageService()
            .getLanguage(new ghidra.program.model.lang.LanguageID("PIC-12:LE:16:PIC-12C5xx"));
    var picCompiler =
        picLanguage.getCompilerSpecByID(new ghidra.program.model.lang.CompilerSpecID("default"));
    var picProgram =
        new ghidra.program.database.ProgramDB("codec_pic_stack", picLanguage, picCompiler, this);
    try {
      var picFactory = picProgram.getAddressFactory();
      var picStack = picFactory.getStackSpace();
      require(picStack.getAddressableUnitSize() == 2, "PIC hardware stack must use word addresses");
      for (long offset :
          new long[] {
            picStack.getMinAddress().getOffset(), -3, -1, 0, picStack.getMaxAddress().getOffset()
          }) {
        roundtrip(picFactory, picStack.getAddress(offset));
      }
      String stackOverflow = picStack.getName() + ":0x7fffffffffffffff.1";
      try {
        AddressCodec.parse(picFactory, stackOverflow);
        throw new AssertionError("Signed stack overflow silently wrapped: " + stackOverflow);
      } catch (IllegalArgumentException expected) {
        // A positive word offset cannot wrap into a valid negative stack byte.
      }
    } finally {
      picProgram.release(this);
    }

    for (String input :
        new String[] {
          "signed_word:0x4000000000000000",
          "signed_word:0x7fffffffffffffff.1",
          "signed_word:0x8000000000000000",
          "signed_word:0xbfffffffffffffff.1"
        }) {
      try {
        AddressCodec.parse(factory, input);
        throw new AssertionError("Signed word overflow silently wrapped: " + input);
      } catch (IllegalArgumentException expected) {
        // Word offsets must fit in the signed byte-offset range.
      }
    }
    require(AddressCodec.format(null) == null, "Null address must stay null");
    require(
        AddressCodec.format(ghidra.program.model.address.Address.NO_ADDRESS) == null,
        "NO_ADDRESS must not become an input address");
    var programFactory = currentProgram.getAddressFactory();
    roundtrip(programFactory, programFactory.getStackSpace().getAddress(-16));
    roundtrip(programFactory, programFactory.getAddressSpace("join").getAddress(1));
    var block =
        currentProgram
            .getMemory()
            .createInitializedBlock(
                "codec_overlay",
                programFactory.getDefaultAddressSpace().getAddress(0x1800),
                4,
                (byte) 0,
                monitor,
                true);
    roundtrip(programFactory, block.getStart());
    var outsideOverlayBlock = AddressCodec.parse(programFactory, "codec_overlay:0x1000");
    require(
        outsideOverlayBlock.getAddressSpace().equals(block.getStart().getAddressSpace()),
        "Overlay address must not substitute the physical space outside its block");
    roundtrip(programFactory, outsideOverlayBlock);
    for (String name : new String[] {"0xbank", "0x1234", "\u2002bank", "bank"}) {
      var namedBlock =
          currentProgram
              .getMemory()
              .createInitializedBlock(
                  name,
                  programFactory.getDefaultAddressSpace().getAddress(0x1900),
                  4,
                  (byte) 0,
                  monitor,
                  true);
      require(
          namedBlock.getStart().getAddressSpace().getName().equals(name),
          "Overlay address-space name was changed: " + name);
      roundtrip(programFactory, namedBlock.getStart());
    }
    var segmented = new ghidra.program.model.address.SegmentedAddressSpace("segmented", 2);
    var segmentedFactory =
        new ghidra.program.model.address.DefaultAddressFactory(
            new ghidra.program.model.address.AddressSpace[] {segmented}, segmented);
    var address = segmented.getAddress(0x1234, 5);
    String text = AddressCodec.format(address);
    require(text.equals("segmented:0x1234:0x0005"), "Segmented format: " + text);
    roundtrip(segmentedFactory, address);
    try {
      AddressCodec.parseCanonical(segmentedFactory, "0x1234:0x0005");
      throw new AssertionError("Canonical endpoint inferred an unnamed segment");
    } catch (IllegalArgumentException expected) {
      // clear endpoints require the space name even in the default space.
    }
    for (String input : new String[] {text, "0X1234:0X0005", "segmented:0x1234:0x0005"}) {
      var parsed =
          (ghidra.program.model.address.SegmentedAddress)
              AddressCodec.parse(segmentedFactory, input);
      require(
          parsed != null && parsed.getSegment() == 0x1234 && parsed.getSegmentOffset() == 5,
          "Lost original segment/offset: " + input);
    }
    var numericSpace =
        new ghidra.program.model.address.GenericAddressSpace(
            "0x1234", 32, ghidra.program.model.address.AddressSpace.TYPE_RAM, 6);
    var ambiguousFactory =
        new ghidra.program.model.address.DefaultAddressFactory(
            new ghidra.program.model.address.AddressSpace[] {segmented, numericSpace}, segmented);
    roundtrip(ambiguousFactory, address);
    roundtrip(ambiguousFactory, numericSpace.getAddress(5));
    require(
        AddressCodec.parse(ambiguousFactory, "0x1234:0x0005")
            .getAddressSpace()
            .equals(numericSpace),
        "Registered numeric-looking address space must take precedence over an unnamed segment");
    for (String input :
        new String[] {
          "1000",
          "ram:1000",
          "FUN_00401000",
          "0x",
          "0xxyz",
          "0x10000000000000000",
          "0x1234:0005",
          "1234:0x0005",
          "segmented:1234:0005"
        }) {
      try {
        require(
            AddressCodec.parse(segmentedFactory, input) == null,
            "Accepted invalid explicit address: " + input);
      } catch (IllegalArgumentException expected) {
        // Parsers may report malformed tokens either as null or an input error.
      }
    }
    var narrow =
        new ghidra.program.model.address.GenericAddressSpace(
            "narrow", 32, ghidra.program.model.address.AddressSpace.TYPE_RAM, 5);
    var mixedFactory =
        new ghidra.program.model.address.DefaultAddressFactory(
            new ghidra.program.model.address.AddressSpace[] {narrow, ram}, narrow);
    for (String input : new String[] {"0x100000000", "0xffffffffffffffff"}) {
      try {
        require(
            AddressCodec.parse(mixedFactory, input) == null,
            "Address overflow silently changed the default space or recovered its sign: " + input);
      } catch (IllegalArgumentException expected) {
        // A larger secondary space cannot rescue overflow in the default space.
      }
    }
    require(
        AddressCodec.parse(mixedFactory, "ram:0xffffffffffffffff").getOffset() == -1L,
        "Explicit secondary 64-bit address must remain valid");
  }
}
