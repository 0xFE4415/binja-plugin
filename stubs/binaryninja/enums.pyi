from enum import IntEnum


class MediumLevelILOperation(IntEnum):
    MLIL_SET_VAR = 0
    MLIL_CONST = 15
    MLIL_CONST_PTR = 16
