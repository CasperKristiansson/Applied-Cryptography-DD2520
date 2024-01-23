# Assignment: Cryptanalysis of Ciphertexts

## Task
Your task is to find the corresponding plaintexts. A cryptanalysis is considered successful if you report a reasonably large prefix of the plaintext as part of your written solution and give a brief description of your analysis.

## Rules
Do not receive or share anything concrete like: code, writeups, ciphertexts, plaintexts, etc, but feel free to discuss the generic problem with a friend and share ideas. In other words, you may work on ideas in pairs, but you must write your own implementation, execute solely your own implementation during analysis, write your own summary, and submit your own solution.

Each student receives unique ciphertexts encrypted with unique keys. The ciphers can be be broken by systematically applying the techniques covered in class.

## Hints
They are encryptions of English plaintexts using the following
alphabet:

0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_#

In other words, only digits, capital letters, underscore-character
"_", and hash character "#" may be occur. An underscore encodes a
space and hash character encodes a newline.

Each ciphertext is represented as a number of newline-separated
rows. You should remove the newlines, i.e., concatenate all the
individual rows to construct the challenge ciphertext.

## Grading
To get a passing grade you must successfully cryptanalyze both ciphertexts. If you fail, you'll have to complement the assignment by doing an oral presentation for Douglas.

| Cryptanalysis      | Criteria                                                                                         | Ratings                      | Pts   |
|--------------------|--------------------------------------------------------------------------------------------------|------------------------------|-------|
| Successful cryptanalysis         | The students has forced the ciphertext if they can provide a large enough prefix of the plaintext. They don't need to give the whole plaintext (it's large).                        | 1 Pts Both ciphertexts forced| 1 pts |
| Relevant analysis  |                                                                                                  | 1 Pts Yes                    | 1 pts |
| Correct analysis   |                                                                                                  | 1 Pts Yes                    | 1 pts |
| **Total points:**  |                                                                                                  |                              | 3     |
