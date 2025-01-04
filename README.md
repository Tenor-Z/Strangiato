# Strangiato
A proof-of-concept virus that I created for my COMP-3-247 - Advanced Investigations class

# Background Information
COMP-3-247 consisted of learning various security practices for mitigating malicious threats, more specifically, different types of malware. For the fourth lab of the class, we were instructed with not only generating a backdoor trojan using MSFVenom, but we were also tasked to create some malware of our own. We could have used Metasploit for both tasks, though I decided to go for the difficult route because I'm a masochistic psychopath

# Malware Behavior
Strangiato is a PE file infector, meaning it targets and appends its code to the end of .EXE files upon execution. To minimize noticeable system damage, the virus skips files that are not signed by Microsoft, as these are likely critical system resources required for the operating system to function.

The presence of the infection can be identified by an increase in the file size of affected files. Originally, the virus was designed to allow the original host code to run after its own code. However, this functionality appears to be non-operational at the moment. As a result, infected files often fail to execute properly or become corrupted. Despite these issues, Strangiato is not considered an overwriting virus, as it employs mechanisms to append its code to the end of infected files rather than replacing the original code entirely.

Additionally, Strangiato enforces a few mechanisms to prevent itself from being removed easily. First, it disables Task Manager and the Registry Editor, limiting backup strategies and delaying the incident response process. Privileges are esculated at the very beginning of execution, though this could be suspicious to some users. For the best case scenario, the virus would have to be cleverly disguised in order to have a lasting impact. Strangiato will place a registry key that will allow it to be executed on the computer's startup, linked to a hidden copy of the file outside of the bounds of traditional users.

# Payloads
The virus contains several payloads, though some are more destructive than others.

On September 29th of any year, the virus will spam various message boxes on the screen, similar to as seen in MEMZ. These boxes will continue to occur and cannot be closed via the Task Manager. The payload will continue for the entire day.

If the date is the 18th of any month, however, the virus will overwrite the Master Boot Record (if applicable), rendering the device inoperable from bootup. If the boot disk is formatted via GPT, this simply will not work.

# Warning
