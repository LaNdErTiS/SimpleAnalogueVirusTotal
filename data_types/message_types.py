import enum


class MessageType(enum.Enum):
    NEW_PROCESS = enum.auto()
    DEL_PROCESS = enum.auto()
    NEW_CONNECTION = enum.auto()
    MEMORY_CHECK_PERFORMED = enum.auto()
    CHK_PACKER_RESULT = enum.auto()
    CHK_SIGNATURE_RESULT = enum.auto()
    CHK_SECTIONS_RESULT = enum.auto()
    CHK_MITRE = enum.auto()
