# Coding Section for Part 2

LOG_FILE_NAME = 'log.txt'

# this logging function just assumes that the functions calling it utilize it correctly, so it simply just appends the message to the log file
# str message: message to be put into the log
def print_to_log(message):
    with open(LOG_FILE_NAME, "a") as log:
        log.write(f"{message}\n")