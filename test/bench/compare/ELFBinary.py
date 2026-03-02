from Binary import Binary
from datapoints.Symbol import Symbol, SymbolType
from datapoints.Data import Addr

from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.elf.sections import SymbolTableSection, Section
import logging as log


def symbol_type(type_str: str) -> SymbolType:
    if type_str == "STT_OBJECT":
        return SymbolType.OBJECT
    elif type_str == "STT_FUNC":
        return SymbolType.FUNCTION
    return SymbolType.UNSPECIFIED


class ELFBinary(Binary):
    def __init__(self, bin_path: Path):
        super().__init__(bin_path)

    def _load_obj(self):
        self.obj = ELFFile.load_from_path(self.path)
        self.has_debug_info = self.obj.has_dwarf_info()
        self._load_functions()

    def can_load(bin_path: Path) -> bool:
        try:
            ELFFile.load_from_path(bin_path)
            return True
        except ELFError as e:
            log.debug(repr(e))
            return False

    def _load_functions(self):
        sec: Section
        for sec in self.obj.iter_sections():
            if sec["sh_type"] != "SHT_SYMTAB" and sec["sh_type"] != "SHT_DYNSYM":
                continue
            log.debug(
                f"Parse section {sec['sh_type']} with {sec.num_symbols()} symbols."
            )

            table: SymbolTableSection = sec
            sym: Symbol
            for sym in table.iter_symbols():
                sym_type = symbol_type(sym.entry["st_info"]["type"])
                sym_size = sym.entry["st_size"]
                loc = sym.entry["st_value"]
                if loc == 0:
                    continue

                symbol = Symbol(sym.name, sym_type, sym_size, loc)
                if sym_type == SymbolType.OBJECT:
                    symbol.add_range((Addr(loc), Addr(loc + sym_size)))
                self.symbols.append(symbol)
        log.debug(f"Loaded {len(self.symbols)} symbols")
        for sym in self.symbols:
            log.debug(f"\t{sym}")
