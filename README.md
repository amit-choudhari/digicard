# digicard
Digital card for festival (Project)

'''
sirius@ubuntu:~/workspace/IPP/INF648/Projects/digicard/Client$ python3 main.py 
========================
commands
-----------------------
1. Enroll: name
2. Enroll: surname
3. Enroll: PIN
4. Enroll: UID
5. Verify: PIN
6. Debit
7. Credit
8. Balance
9. Exchange
10. GetInfo
11. Exit
0. Test
=======================

Select cmd:1
Enter Name:Amit
Integrity check passed.. decrypting
enrolled name: Amit
-------

Select cmd:2
Enter Surname:Choudhari
Integrity check passed.. decrypting
enrolled surname: Choudhari
-------

Select cmd:3
Enter New PIN:123456
Integrity check passed.. decrypting
Enrolled PIN!
-------

Select cmd:4
Enter New UID:1234
Integrity check passed.. decrypting
Enrolled UID [49, 50, 51, 52]
-------

Select cmd:5
Enter PIN:123456
Integrity check passed.. decrypting
Status:  code bon!
-------

Select cmd:7
Enter amount:100
Integrity check passed.. decrypting
Credit:  100
-------

Select cmd:6
Enter amount:10
Integrity check passed.. decrypting
Debit: 10
-------

Select cmd:8
Integrity check passed.. decrypting
Balance:  90
-------

Select cmd:11
Enjoy the Festival!!

'''
