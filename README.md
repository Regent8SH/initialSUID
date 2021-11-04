# initialSUID
Quick SUID test, for easier SUID enumeration

Python script to check for SUID binaries and remove standard entries for easier enumeration. Yeah linenum probably already does this... oh well.

use the script with basic input:
./initialSUID.py

Script executes the basic SUID enumeration:
find / -type f -perm -u=s -exec ls -ldb {} \; 2>/dev/null

Only prints entries that are not SUID binaries that are commonly distributed. Script is written to allow easy modification of the coommon SUID binary list.
