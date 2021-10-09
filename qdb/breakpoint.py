class Breakpoint(object):
    """
    Breakpoint
    """
    def __init__(self, address):
        self.hook = None
        self.hitted = False
        self.address = address


class TempBreakpoint(Breakpoint):
    """
    Temporary breakpoint
    """
