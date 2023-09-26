## Semgrep

1. SQL注入漏洞检测规则：

```yaml
rules:
  - id: java-sql-injection
    metadata:
      severity: high
      description: Detects potential SQL injection vulnerabilities in Java code.
    languages:
      - java
    patterns:
      - pattern: |
          $query = $1;
          $query taintedBy $userInput;
          $dbConnection.query($query)
        message: "Potential SQL injection vulnerability: Unsanitized use of tainted input ($userInput) in database query."
        capture:
          - variable: $query
            pattern: "\\b(?!PreparedStatement)\\w+\\.query\\("
          - variable: $userInput
            pattern: "\\b(\\w+)\\b"
```

测试代码：

```java
import java.sql.*;

public class TestApp {
    public static void main(String[] args) {
        String userInput = "'; DROP TABLE users;--";
        String query = "SELECT * FROM products WHERE id = '" + userInput + "'";

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "username", "password");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                String productName = rs.getString("name");
                System.out.println(productName);
            }

            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
```





2. 文件路径遍历漏洞检测规则：

   ```yaml
   rules:
     - id: java-file-path-traversal
       metadata:
         severity: high
         description: Detects potential file path traversal vulnerabilities in Java code.
       languages:
         - java
       patterns:
         - pattern: |
             $filePath = $1;
             $filePath taintedBy $userInput;
             $fileIO.readFile($filePath)
           message: "Potential file path traversal vulnerability: Unsanitized use of tainted input ($userInput) in file access."
           capture:
             - variable: $filePath
               pattern: "\\b(?!Path)\\w+\\.read(File|FileInputStream)\\("
             - variable: $userInput
               pattern: "\\b(\\w+)\\b"
   ```

   测试代码：

   ```java
   import java.io.*;
   
   public class TestApp {
       public static void main(String[] args) {
           String userInput = "../confidential.txt";
           String filePath = "/var/www/data/" + userInput;
           
           try {
               File file = new File(filePath);
               BufferedReader reader = new BufferedReader(new FileReader(file));
               String line;
               
               while ((line = reader.readLine()) != null) {
                   System.out.println(line);
               }
               
               reader.close();
           } catch (IOException e) {
               e.printStackTrace();
           }
       }
   }
   ```

   

3. 命令注入漏洞检测规则:

   ```yaml
   rules:
     - id: java-command-injection
       metadata:
         severity: high
         description: Detects potential command injection vulnerabilities in Java code.
       languages:
         - java
       patterns:
         - pattern: $command taintedBy $userInput
           message: "Potential command injection vulnerability: Unsanitized use of tainted input ($userInput) in command execution."
           capture:
             - variable: $command
               pattern: Runtime\.exec\($EXP\)
             - variable: $userInput
               pattern: \b(\\w+)\b
   ```

   测试代码：

   ```java
   import java.io.*;
   
   public class TestApp {
       public static void main(String[] args) {
           String userInput = "127.0.0.1; rm -rf /";
           String command = "ping " + userInput;
           
           try {
               Process process = Runtime.getRuntime().exec(command);
               BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
               String line;
               
               while ((line = reader.readLine()) != null) {
                   System.out.println(line);
               }
               
               reader.close();
           } catch (IOException e) {
               e.printStackTrace();
           }
       }
   }
   ```

   