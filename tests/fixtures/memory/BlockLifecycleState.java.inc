
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    private void checkState(ghidra.program.model.listing.Program p, long start, boolean deleted)
            throws Exception {
        var space = p.getAddressFactory().getDefaultAddressSpace();
        var code = space.getAddress(start);
        var outside = space.getAddress(0x4000);
        var memory = p.getMemory();
        var listing = p.getListing();
        require(p.getImageBase().getOffset() == 0x1000, "Block operation changed image base");
        require(!ghidra.program.util.GhidraProgramUtilities.isAnalyzed(p), "Operation ran analysis");
        require(memory.getBlock("outside").getStart().equals(outside), "Other block moved");
        require(memory.getByte(outside) == (byte) 0x90, "Outside byte changed");
        require("outside comment".equals(listing.getComment(
            ghidra.program.model.listing.CodeUnit.EOL_COMMENT, outside)), "Outside comment changed");
        require(p.getSymbolTable().getGlobalSymbol("outside_label", outside.add(0x30)) != null,
            "Outside label changed");
        var pointer = listing.getDataAt(outside.add(0x40));
        require(pointer != null && pointer.getValue() instanceof ghidra.program.model.address.Address
            && ((ghidra.program.model.address.Address) pointer.getValue()).getOffset() == 0x2000,
            "Embedded pointer bytes were rewritten or its definition was removed");
        require(memory.getAllFileBytes().size() == 1, "Stored FileBytes were removed");
        var file = memory.getAllFileBytes().get(0);
        require(file.getFilename().equals("block-original") && file.getFileOffset() == 0x200
            && file.getSize() == 0x110 && file.getOriginalByte(8) == (byte) 0xb8
            && file.getOriginalByte(0x58) == (byte) 0x55, "Stored original changed");
        var functions = p.getFunctionManager();
        var refs = p.getReferenceManager();
        // Native block movement/removal keeps outside reference sources and their
        // absolute destinations, including destinations no longer backed by memory.
        for (long[] entry : new long[][] {{0x50, 0x2000}, {0x58, 0x6000}}) {
            var incoming = refs.getReference(outside.add(entry[0]), space.getAddress(entry[1]), 0);
            require(incoming != null && incoming.getSource()
                == ghidra.program.model.symbol.SourceType.USER_DEFINED,
                "Outside reference destination changed");
        }
        if (deleted) {
            require(memory.getBlock(code) == null, "Deleted memory remains");
            require(listing.getInstructionAt(code) == null, "Deleted instruction remains");
            require(listing.getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, code) == null,
                "Deleted comment remains");
            require(p.getSymbolTable().getSymbols(code.add(0x30)).length == 0, "Deleted label remains");
            require(functions.getFunctionAt(code) == null && functions.getFunctionAt(outside) == null,
                "Functions intersecting the deleted block remain");
            require(refs.getReferencesFrom(code.add(0x60)).length == 0,
                "Reference originating in deleted memory remains");
            return;
        }
        var block = memory.getBlock(code);
        require(block != null && block.getStart().equals(code) && block.getSize() == 0x100,
            "Block range differs");
        require(block.isExecute() && block.isInitialized(), "Block attributes changed");
        require(block.getSourceInfos().get(0).getFileBytesOffset(code) == 8,
            "Moved block lost direct FileBytes mapping");
        byte[] actual = new byte[6];
        memory.getBytes(code, actual);
        require(java.util.Arrays.equals(actual,
            new byte[]{(byte) 0xb8, 0x11, 0x22, 0x33, 0x44, (byte) 0xc3}), "Instruction bytes changed");
        require(memory.getByte(code.add(0x50)) == (byte) 0x7f, "Patched byte was lost");
        require(listing.getInstructionAt(code) != null && listing.getInstructionAt(code.add(5)) != null
            && listing.getInstructionAt(code.add(0x20)) == null, "Instruction definitions changed");
        require("moving comment".equals(listing.getComment(
            ghidra.program.model.listing.CodeUnit.EOL_COMMENT, code)), "Comment did not move");
        require(p.getSymbolTable().getGlobalSymbol("moving_label", code.add(0x30)) != null,
            "Label did not move");
        var insideFunction = functions.getFunctionAt(code);
        require(insideFunction != null && insideFunction.getName().equals("inside_entry")
            && insideFunction.getBody().contains(code.add(5))
            && insideFunction.getBody().contains(outside.add(0x25))
            && insideFunction.getBody().getNumAddresses() == 12, "Inside-entry function body differs");
        var outsideFunction = functions.getFunctionAt(outside);
        require(outsideFunction != null && outsideFunction.getName().equals("outside_entry")
            && outsideFunction.getBody().contains(code.add(0x25))
            && outsideFunction.getBody().contains(outside.add(5))
            && outsideFunction.getBody().getNumAddresses() == 12, "Outside-entry function body differs");
        require(refs.getReference(code.add(0x60), outside.add(0x30), 0) != null,
            "Reference origin did not follow block movement");
        if (start != 0x2000) {
            var old = space.getAddress(0x2000);
            require(memory.getBlock(old) == null && listing.getInstructionAt(old) == null
                && functions.getFunctionAt(old) == null, "Old address retained moved content");
            require(listing.getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, old) == null
                && p.getSymbolTable().getSymbols(old.add(0x30)).length == 0, "Old address retained metadata");
        }
    }
