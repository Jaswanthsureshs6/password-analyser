Password Strength Analyzer

Features

Scoring: Length (+1-2), upper/lower/digits/symbols (+1 each), common penalties, entropy bonus (>50 bits +1).
Leaks: HashSet O(1) lookups from leaked_passwords.txt.
Suggestions & Reports: Dynamic advice + masked TXT logs.
Tech: Java 8+ (Scanner, Regex, BufferedReader, StringBuilder, Math.log).

 Setup & Run
1. `git clone https://github.com/Jaswanthsureshs6/password-analyser.git`
2. `cd password-analyser`
3. `javac PasswordAnalyzer.java`
4. `java PasswordAnalyzer`.
