# # Save this script to a file, e.g., print_interp_head.py

# import gdb

# class PrintInterpHead(gdb.Command):
#     """Print the _PyRuntime struct and access the interpreters.head field."""

#     def __init__(self):
#         super(PrintInterpHead, self).__init__("print_interp_head", gdb.COMMAND_USER)

#     def invoke(self, arg, from_tty):
#         try:
#             runtime = gdb.parse_and_eval('_PyRuntime')
#             interpreters_head = runtime['interpreters']['head']
            
#             # Print the content of the structure
#             print("\nPrinting interpreters.head structure:")
#             print(interpreters_head.dereference())
            
#         except Exception as e:
#             print("Error:", str(e))

# # Instantiate the command
# PrintInterpHead()

import gdb

class PrintInterpHead(gdb.Command):
    """Print the _PyRuntime struct, access the interpreters.head.threads.head, and print the linked list of frames."""

    def __init__(self):
        super(PrintInterpHead, self).__init__("print_interp_head", gdb.COMMAND_USER)

    def print_frame_linked_list(self, frame):
        """Print the linked list of frames."""
        while frame != 0:
            print("Frame address:", frame.address)
            print("Frame code:", frame['f_code'])
            print("Frame code.co_filename:", frame['f_code']['co_filename'])
            print("Frame code.co_name:", frame['f_code']['co_name'])
            print("")
            frame = frame['previous']

    def print_thread_info(self, thread):
        """Print information about the thread."""
        print("\nThread ID:", thread['thread_id'])
        print("\nLinked List of Frames:")
        self.print_frame_linked_list(thread['cframe']['current_frame'])

    def invoke(self, arg, from_tty):
        try:
            runtime = gdb.parse_and_eval('_PyRuntime')
            interpreters_head = runtime['interpreters']['head']

            thread = interpreters_head['threads']['head']
            
            # Iterate over the linked list of threads
            while thread != 0:
                self.print_thread_info(thread)
                thread = thread['next']

        except Exception as e:
            print("Error:", str(e))

# Instantiate the command
PrintInterpHead()