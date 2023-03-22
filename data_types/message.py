from data_types.message_types import *


class Message:
    type: MessageType
    data: dict

    def __init__(self, msg_type: MessageType, **kwargs):
        self.type = msg_type
        for key in kwargs:
            setattr(self, key, kwargs[key])
