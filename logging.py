# Coding Section for Part 2

# this logging function just assumes that the functions calling it utilize it correctly, so it simply just appends the message to the log file
# str message: message to be put into the log
def print_to_log(message):
    with open("log.txt", "a") as log:
        log.write(f"{message}\n")