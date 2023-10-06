# 知识点

| **双指针、滑动窗口**                        | 🐕    |
| ------------------------------------------- | ---- |
| **排序（自定义Comparator）+排序算法的应用** | 🐕    |
| **位运算、进制转换**                        |      |
| **二分搜索、归并**                          |      |
| **BFS、DFS**                                |      |
| **回溯算法**、递归                          |      |
| **贪心**                                    |      |
| **栈+单调栈**                               |      |
| **二叉树**（考察构建和遍历）                | 🐕    |
| **队列、优先队列（工作级不要求）**          |      |
| **股票买卖问题**                            |      |
| **区间求和问题、前缀和、树状数组、线段树**  |      |
| **动态规划（工作级不要求）**                |      |

涉及的数据结构与算法：

1. 进制与位运算；
2. 基础的数据结构（字符串、数组、队列、栈、链表、哈希）；
3. 高级数据结构（树）；
4. 优先队列、图；
5. 排序与查找；
6. 枚举（遍历、排序、组合）、滑动窗口、双指针、前缀和；
7. 迭代、递归、回溯、分支（归并、二分）、搜索（深搜、广搜）、贪心；

## 基础的数据结构

#### [13. 罗马数字转整数](https://leetcode.cn/problems/roman-to-integer/)

字符串 + HashMap

```java
class Solution {
    public int romanToInt(String s) {
        Map<Character,Integer> roman = new HashMap<>();
        roman.put('I',1);
        roman.put('V',5);
        roman.put('X',10);
        roman.put('L',50);
        roman.put('C',100);
        roman.put('D',500);
        roman.put('M',1000);
        int res = 0;
        for(int i = 0; i<s.length()-1;i++){
            if(roman.get(s.charAt(i)) >= roman.get(s.charAt(i+1))){
                res += roman.get(s.charAt(i));
            }else{
                res -= roman.get(s.charAt(i));
            }
        }
        res += roman.get(s.charAt(s.length() - 1));
        return res;
    }
}
```

#### [6. N 字形变换](https://leetcode.cn/problems/zigzag-conversion/)

该题有一个巧妙点，用一个 flag判断curRow是往下还是往上！

```java
class Solution {
    public String convert(String s, int numRows) {
        StringBuilder[] res = new  StringBuilder[numRows];
        for (int i = 0; i < numRows; i++) {
            res[i] = new StringBuilder();
        }
        if (numRows == 1) return s;
        int curRow = 0;
        boolean goDown = false;
        for (char c : s.toCharArray()) {
            res[curRow].append(c);
            if (curRow == 0 || curRow == numRows - 1){//在首行和尾行变换方向！
                goDown = !goDown;
            }
            curRow += goDown?1:-1;
        }
        StringBuilder resF = new StringBuilder();
        for (StringBuilder sb : res) {
            resF.append(sb);
        }
        return resF.toString();
    }
}
```

#### [43. 字符串相乘](https://leetcode.cn/problems/multiply-strings/)

```java
class Solution {
    public String multiply(String num1, String num2) {
        int m = num1.length();
        int n = num2.length();
        int[] res = new int[m + n];
        for (int i = m - 1; i >= 0; i--) {
            for (int j = n - 1; j >= 0; j--) {
                int mul = (num1.charAt(i) - '0') * (num2.charAt(j) - '0');
                int p1 = i + j;//进位需要相加的位置
                int p2 = i + j + 1;//结果的余数
                int sum = mul + res[p2];
                res[p2] = sum % 10;
                res[p1] += sum / 10;

            }
        }
        // 结果前缀可能存的 0（未使用的位）
        int k = 0;
        while (k < res.length && res[k] == 0)
            k++;
        // 将计算结果转化成字符串
        StringBuilder sb = new StringBuilder();
        for (; k < res.length; k++)
            sb.append(res[k]);
        
        String str = sb.toString();
        return str.length() == 0 ? "0" : str;
    }
    
}
```

#### [621. 任务调度器](https://leetcode.cn/problems/task-scheduler/)

```java
class Solution {
    public int leastInterval(char[] tasks, int n) {
        int[] cnts = new int[26];
        for (char c : tasks) cnts[c - 'A']++;
        int max = 0, tot = 0;
        for (int i = 0; i < 26; i++) max = Math.max(max, cnts[i]);
        for (int i = 0; i < 26; i++) tot += max == cnts[i] ? 1 : 0;
        return Math.max(tasks.length, (n + 1) * (max - 1) + tot);
    }
}
此题为巧妙的找规律题目，参考下面解法
https://leetcode.cn/problems/task-scheduler/solution/by-ac_oier-3560/
```

#### [20. 有效的括号](https://leetcode.cn/problems/valid-parentheses/)

```ja
class Solution {
    public boolean isValid(String s) {
        Stack<Character> stack = new Stack<>();
        for (char c : s.toCharArray()) {
            if (c == '(' || c == '{' || c == '['){
                stack.push(c);
            }else {
                if (!stack.isEmpty() && leftOf(c) == stack.peek()){
                    stack.pop();
                }else return false;
            }
        }
        return stack.isEmpty();
    }
    char leftOf(char c) {
        if (c == '}') return '{';
        if (c == ')') return '(';
        return '[';
    }
}
```

#### [150. 逆波兰表达式求值](https://leetcode.cn/problems/evaluate-reverse-polish-notation/)

```java
class Solution {
    public int evalRPN(String[] tokens) {
        Stack<Integer> stk = new Stack<>();
        for (String token : tokens) {
            if ("+-*/".contains(token)) {
                // 是个运算符，从栈顶拿出两个数字进行运算，运算结果入栈
                int a = stk.pop(), b = stk.pop();
                switch (token) {
                    case "+":
                        stk.push(a + b);
                        break;
                    case "*":
                        stk.push(a * b);
                        break;
                    // 对于减法和除法，顺序别搞反了，第二个数是被除（减）数
                    case "-":
                        stk.push(b - a);
                        break;
                    case "/":
                        stk.push(b / a);
                        break;
                }
            } else {
                // 是个数字，直接入栈即可
                stk.push(Integer.parseInt(token));
            }
        }
        // 最后栈中剩下一个数字，即是计算结果
        return stk.pop();
    }
}
```

## **双指针**

#### [26. 删除有序数组中的重复项](https://leetcode.cn/problems/remove-duplicates-from-sorted-array/)

让慢指针 `slow` 走在后面，快指针 `fast` 走在前面探路，找到一个不重复的元素就赋值给 `slow` 并让 `slow` 前进一步。这样，就保证了 `nums[0..slow]` 都是无重复的元素，当 `fast` 指针遍历完整个数组 `nums` 后，`nums[0..slow]` 就是整个数组去重之后的结果。

``` java
class Solution {
    public int removeDuplicates(int[] nums) {
        if(nums.length == 0){
            return 0;
        }
        int slow = 0;
        int fast = 0;
        while(fast < nums.length){
            if(nums[fast] != nums [slow]){
                slow++;
                nums[slow] = nums[fast]; 
            }
            fast++;
        }
        return slow + 1;
    }
}
```



#### **[443. 压缩字符串](https://leetcode.cn/problems/string-compression/)**

**边界条件很多，案例容易出错**

```java
class Solution {
    public static int compress(char[] chars) {
        int left = 0;
        int right = 0;
        while (right < chars.length) {
            int index = right;//记录新字母开始时的位置
            while(right < chars.length && chars[index] == chars[right]){
                right++;
            }
            int repeats = right - index;
            chars[left] = chars[right - 1];//需要时刻保持left的更新
            if(repeats == 1){
                left++;
            }else if(repeats <= 9){
                chars[left + 1] = (char)(repeats + '0');
                left += 2;
            }else{
                String num = repeats + "";
                for(int i = 0; i < num.length();i++){
                    chars[left + 1 + i] = num.charAt(i);
                }
                left += num.length() + 1;
            }
        }


        return left;
    }
}
```

#### **[5. 最长回文子串](https://leetcode.cn/problems/longest-palindromic-substring/)**

**每次循环都将子串考虑为偶数长度和基数长度，取和res比较三者最长的回文串**

```java
class Solution {
    public String longestPalindrome(String s) {
        String res = "";
        for(int i = 0; i<s.length();i++){
            String s1 = Palindrome(s,i,i);
            String s2 = Palindrome(s,i,i+1);
            res = res.length() > s1.length()?res:s1;
            res = res.length() > s2.length()?res:s2;
        }
        return res;
    }
    public String Palindrome(String s, int left, int right){
        while(left >= 0 && right < s.length() && s.charAt(left) == s.charAt(right)){
            left--;
            right++;
        }
        return s.substring(left+1,right);
    }
}
```

#### **[283. 移动零](https://leetcode.cn/problems/move-zeroes/)**

```java
class Solution {
    public void moveZeroes(int[] nums) {
        int slow = 0;
        for(int fast = 0;fast<nums.length;fast++){
            if(nums[fast]!= 0){
                nums[slow++] = nums[fast];
            }
        }
        for(int i = slow;i<nums.length;i++){
            nums[i] = 0;
        }
    }
}
```

#### **[19. 删除链表的倒数第 N 个结点](https://leetcode.cn/problems/remove-nth-node-from-end-of-list/)**

**这个逻辑就很简单了，要删除倒数第 `n` 个节点，就得获得倒数第 `n + 1` 个节点的引用，可以用我们实现的 `findFromEnd` 来操作。**

**使用了虚拟头结点的技巧，也是为了防止出现空指针的情况，比如说链表总共有 5 个节点，题目就让你删除倒数第 5 个节点，也就是第一个节点，那按照算法逻辑，应该首先找到倒数第 6 个节点。但第一个节点前面已经没有节点了，这就会出错。**

**但有了我们虚拟节点 `dummy` 的存在，就避免了这个问题，能够对这种情况进行正确的删除。**

```java
class Solution {
    public ListNode removeNthFromEnd(ListNode head, int n) {
        ListNode dummy = new ListNode(-1);
        dummy.next = head;
        ListNode x = findFromEnd(dummy, n + 1);
        x.next = x.next.next;
        return dummy.next;
    }
    private ListNode findFromEnd(ListNode head,int k){
        // p1 先走 k 步
        ListNode p1 = head;
        for (int i = 0; i < k; i++) {
            p1 = p1.next;
        }
        ListNode p2 = head;
        // p1 和 p2 同时走 n - k 步
        while (p1!=null){
            p1 = p1.next;
            p2 = p2.next;
        }
        // p2 现在指向第 n - k + 1 个节点，即倒数第 k 个节点
        return p2;
    }
}
```

#### **[142. 环形链表 II](https://leetcode.cn/problems/linked-list-cycle-ii/)**

**返回链表开始入环的第一个节点。 *如果链表无环，则返回 `null`。***

**每当慢指针 `slow` 前进一步，快指针 `fast` 就前进两步。**

**如果 `fast` 最终遇到空指针，说明链表中没有环；如果 `fast` 最终和 `slow` 相遇，那肯定是 `fast` 超过了 `slow` 一圈，说明链表中含有环。**

```java
public class Solution {
    public ListNode detectCycle(ListNode head) {
        ListNode slow = head,fast = head;
        while(fast != null && fast.next != null){
            slow = slow.next;
            fast = fast.next.next;
            if(fast == slow) break;
        }
        if(fast == null || fast.next == null){
            return null;
        }
        slow = head;
        while(slow != fast){
            slow = slow.next;
            fast = fast.next;
        }
        return slow;
    }
}
```

#### [11. 盛最多水的容器](https://leetcode.cn/problems/container-with-most-water/)



![](https://maekdowm-wbb.oss-cn-hangzhou.aliyuncs.com/img/image-20231005235002125.png)

> if 语句为什么要移动较低的⼀边：
> ```java
> if (height[left] < height[right]) {
> 	left++;
> } else {
> 	right--;
> }
> ```
>
>
> 其实也好理解，因为矩形的⾼度是由 min(height[left], height[right]) 即较低的⼀边决定的：**如果移动较低的那⼀边，那条边可能会变⾼，使得矩形的⾼度变⼤，进⽽就「有可能」使得矩形的⾯积变⼤**；相反，如果你去移动较⾼的那⼀边，矩形的⾼度是⽆论如何都不会变⼤的，所以不可能使矩形的⾯积变得更⼤。  

## 滑动窗口

#### 基本算法框架

```java
/* 滑动窗口算法框架 */
void slidingWindow(String s) {
    // 用合适的数据结构记录窗口中的数据
    HashMap<Character, Integer> window = new HashMap<>();

    int left = 0, right = 0;
    while (right < s.length()) {
        // c 是将移入窗口的字符
        char c = s.charAt(right);
        window.put(c, window.getOrDefault(c, 0) + 1);
        // 增大窗口
        right++;
        // 进行窗口内数据的一系列更新
        ...

        /*** debug 输出的位置 ***/
        // 注意在最终的解法代码中不要 print
        // 因为 IO 操作很耗时，可能导致超时
        System.out.printf("window: [%d, %d)\n", left, right);
        /********************/

        // 判断左侧窗口是否要收缩
        while (left < right && window needs shrink) {
            // d 是将移出窗口的字符
            char d = s.charAt(left);
            window.put(d, window.get(d) - 1);
            // 缩小窗口
            left++;
            // 进行窗口内数据的一系列更新
            ...
        }
    }
}
```

#### [643. 子数组最大平均数](https://leetcode.cn/problems/maximum-average-subarray-i/)

```java
    public double findMaxAverage(int[] nums, int k) {
        int sum = 0;
        int n = nums.length;
        for (int i = 0; i < k; i++) {
            sum += nums[i];
        }
        int maxSum = sum;
        for (int i = k; i < n; i++) {
            sum = sum - nums[i - k] + nums[i];
            maxSum = Math.max(maxSum, sum);
        }
        return 1.0 * maxSum / k;
    }
```



#### [76. 最小覆盖子串](https://leetcode.cn/problems/minimum-window-substring/)

```java
class Solution {
    public static String minWindow(String s, String t) {
        Map<Character, Integer> need = new HashMap<>();
        Map<Character, Integer> window = new HashMap<>();
        for (char c : t.toCharArray()) {// 统计 t 中各字符出现次数
            need.put(c, need.getOrDefault(c, 0) + 1);
        }
        int left = 0, right = 0;
        int valid = 0;// 窗口中满足需要的字符个数
        // 记录最小覆盖子串的起始索引及长度
        int start = 0, len = Integer.MAX_VALUE;
        while (right < s.length()) {
            char c = s.charAt(right);// c 是将移入窗口的字符
            right++;// 扩大窗口
            if (need.containsKey(c)) {// 进行窗口内数据的一系列更新
                window.put(c, window.getOrDefault(c, 0) + 1);
                if (window.get(c).equals(need.get(c))) {
                    valid++;
                }
            }
            // 判断左侧窗口是否要收缩
            while (valid == need.size()) {
                if (right - left < len) {// 更新最小覆盖子串
                    start = left;
                    len = right - left;
                }
                char d = s.charAt(left);// d 是将移出窗口的字符
                left++;
                if (need.containsKey(d)) {// 进行窗口内数据的一系列更新
                    if (window.get(d).equals(need.get(d))) {
                        valid--;
                    }
                    window.put(d, window.get(d) - 1);
                }
            }
        }
        return len == Integer.MAX_VALUE ? "" : s.substring(start, start + len);
    }
}
```

#### [567. 字符串的排列](https://leetcode.cn/problems/permutation-in-string/)

**相当给你一个 `S` 和一个 `T`，请问你 `S` 中是否存在一个子串，包含 `T` 中所有字符且不包含其他字符,典型的滑窗**

```java
class Solution {
    public boolean checkInclusion(String t, String s) {
        Map<Character, Integer> need = new HashMap<>();
        Map<Character, Integer> window = new HashMap<>();
        for (char c : t.toCharArray()) {
            need.put(c, need.getOrDefault(c, 0) + 1);
        }
        int left = 0 ,right = 0;
        int valid = 0;
        while (right < s.length()){
            char c = s.charAt(right);
            right++;
            if (need.containsKey(c)){
                window.put(c, window.getOrDefault(c,0)+1);
                if (window.get(c).equals(need.get(c))){
                    valid++;
                }
            }
            while (right - left >= t.length()){
                if (valid == need.size()){
                    return true;
                }
                char d = s.charAt(left);
                left++;
                if (need.containsKey(d)){
                    if (window.get(d).equals(need.get(d))){
                        valid --;
                    }
                    window.put(d, window.getOrDefault(d,0) - 1);
                }
            }
        }
        return false;
    }
}
```

#### [438. 找到字符串中所有字母异位词](https://leetcode.cn/problems/find-all-anagrams-in-a-string/)

跟上一题基本一模一样，只是每次找到valid的排列，都存入其left，其他代码不变，就只改一行;

```java
class Solution {
    public List<Integer> findAnagrams(String s, String p) {
        Map<Character, Integer> need = new HashMap<>();
        Map<Character, Integer> window = new HashMap<>();
        List<Integer> res = new ArrayList<>(); // 记录结果
        for (char c : p.toCharArray()) {
            need.put(c, need.getOrDefault(c, 0) + 1);
        }
        int left = 0 ,right = 0;
        int valid = 0;
        while (right < s.length()){
            char c = s.charAt(right);
            right++;
            if (need.containsKey(c)){
                window.put(c, window.getOrDefault(c,0)+1);
                if (window.get(c).equals(need.get(c))){
                    valid++;
                }
            }
            while (right - left >= p.length()){
                if (valid == need.size()){
                    res.add(left);
                }
                char d = s.charAt(left);
                left++;
                if (need.containsKey(d)){
                    if (window.get(d).equals(need.get(d))){
                        valid --;
                    }
                    window.put(d, window.getOrDefault(d,0) - 1);
                }
            }
        }
        return res;
    }
}
```

#### [3. 无重复字符的最长子串](https://leetcode.cn/problems/longest-substring-without-repeating-characters/)

左窗口收缩条件 **window.get(c) > 1**，满足无重复字符！

```java
class Solution {
    public int lengthOfLongestSubstring(String s) {
        Map<Character, Integer> window = new HashMap<>();
        int left = 0, right = 0;
        int res = 0;
        while(right < s.length()){
            char c = s.charAt(right);
            right++;
            window.put(c, window.getOrDefault(c, 0) + 1);
            //左窗口收缩条件
            while(window.get(c) > 1){
                char d = s.charAt(left);
                left++;
                window.put(d,window.get(d) - 1);
            }
            res = Math.max(res,right - left);//收缩完成后一定保证窗口中没有重复,此时才更新res
        }
        return res;
    }
}
```

#### [239. 滑动窗口最大值](https://leetcode.cn/problems/sliding-window-maximum/)

![img](C:\Users\Windows\Desktop\TyporaImages\1.png)

```java
class Solution {
    public int[] maxSlidingWindow(int[] nums, int k) {
        if(nums == null || nums.length < 2){
            return nums;
        }
        LinkedList<Integer> queue = new LinkedList<>();
        int n = nums.length;
        int[] result = new int[n - k + 1];
        for(int i = 0; i<n;i++){
            while(!queue.isEmpty() && nums[queue.peekLast()] < nums[i]){
                queue.pollLast();//弹出队尾
            }
            while(!queue.isEmpty() && queue.peek() < i - k + 1){
                queue.poll();//弹出队首
            }
            queue.addLast(i);
            if(i >= k-1){
                result[i+1-k] = nums[queue.peek()];
            }
        }
        return result;
    }
}
```

#### 1208. 尽可能使字符串相等

给你两个长度相同的字符串，s 和 t。

将 s 中的第 i 个字符变到 t 中的第 i 个字符需要 |s[i] - t[i]| 的开销（开销可能为 0），也就是两个字符的 ASCII 码值的差的绝对值。

用于变更字符串的最大预算是 maxCost。在转化字符串时，总开销应当小于等于该预算，这也意味着字符串的转化可能是不完全的。

如果你可以将 s 的子字符串转化为它在 t 中对应的子字符串，则返回可以转化的最大长度。

如果 s 中没有子字符串可以转化成 t 中对应的子字符串，则返回 0。


示例 1：

输入：s = "abcd", t = "bcdf", maxCost = 3
输出：3
解释：s 中的 "abc" 可以变为 "bcd"。开销为 3，所以最大长度为 3。

```java
class Solution {
    public int equalSubstring(String s, String t, int maxCost) {
        int[] cost = new int[s.length()];
        for (int i = 0; i < s.length(); i++) {
            cost[i] = Math.abs(s.charAt(i) - t.charAt(i));
        }
        int left = 0;
        int right = 0;
        int costWindow = 0;
        int maxLen = Integer.MIN_VALUE;
        while (right<s.length()){
            costWindow += cost[right];
            while (costWindow > maxCost){
                costWindow -= cost[left];
                left++;
            }
            maxLen = Math.max(maxLen ,right - left + 1);
            right++;
        }
        return maxLen;
    }
}
```

#### [209. 长度最小的子数组](https://leetcode.cn/problems/minimum-size-subarray-sum/)

给定一个含有 `n` 个正整数的数组和一个正整数 `target` **。**

找出该数组中满足其总和**大于等于** `target` 的长度最小的 **连续子数组** `[numsl, numsl+1, ..., numsr-1, numsr]` ，并返回其长度**。**如果不存在符合条件的子数组，返回 `0` 。

```java
class Solution {
    public int minSubArrayLen(int target, int[] nums) {
        int result = Integer.MAX_VALUE;
        int left = 0;
        int sum = 0;
        for(int right = 0; right<nums.length;right++){
            sum += nums[right];
            while(sum >= target){
                int sublen = right - left + 1;
                result = Math.min(result,sublen);
                sum -= nums[left++];
            }
        }
        return result == Integer.MAX_VALUE?0:result;

    }
}
精髓在于 在第二个while循环（缩小窗口的循环中），不断缩小左边界，以找到最短
```



#### 1100. 长度为 K 的无重复字符子串

给你一个字符串 S，找出所有长度为 K 且不含重复字符的子串，请你返回全部满足要求的子串的数目。

> 示例 1：
> 输入：S = “havefunonleetcode”, K = 5
> 输出：6
> 解释：
> 这里有 6 个满足题意的子串，分别是：‘havef’,‘avefu’,‘vefun’,‘efuno’,‘etcod’,‘tcode’。

> 示例 2：
> 输入：S = “home”, K = 5
> 输出：0
> 解释：
> 注意：K 可能会大于 S 的长度。在这种情况下，就无法找到任何长度为 K 的子串。

思路：

- 用一个Hashmap来存窗口内字符出现的次数；
- 这个题关键点是，所有符合题意的子串长度都是固定k，且不允许重复；
- 那我们可以考虑初始化Hashmap时，将S的前K个字符存起来；如果map的size等于k，说明每一个字符只出现了一次；这个点很关键！！！！
- 之后就是一个for循环控制右边界（左边界也跟着每次右移），后面的步骤就是移除左边界的元素，如果左边界元素移除后map中对应的value为0，要remove掉这个左边界元素key；
- 然后把右边界的值加入，加入后判断map大小，和前面一样，如果map.size == K,则符合条件，结果加一！

```java
    public static  int getSubstring(int k,String s){
        int res = 0;
        if(s.length() < k){
            return res;
        }

        HashMap<Character,Integer> map = new HashMap<>();
        for (int i = 0; i < k; i++) {
            map.put(s.charAt(i),map.getOrDefault(s.charAt(i),0) + 1);
        }
        if (map.size()==k) res+=1;
        int left = 0;
        for (int index = k;index<s.length();index++){
            char leftC = s.charAt(left);
            map.put(leftC,map.get(leftC)-1);
            left++;
            if (map.get(leftC) == 0){
                map.remove(leftC);
            }
            char rightC = s.charAt(index);
            map.put(rightC,map.getOrDefault(rightC,0) + 1);
            if (map.size() == k){
                res++;
            }
        }
        return res;
    }
```



#### [1004. 最大连续1的个数 III](https://leetcode.cn/problems/max-consecutive-ones-iii/)

> 思路
> 其实，将K个0转换为1之后，连续的1组成的子数组长度为最长，这个问题可以转换为：
>
> 在数组中取一个窗口，其中的0的个数最多为K个，怎样将这个子数组取得最长。
>
> 将窗口的左端点先设定为0，右端点从0开始往右滑动，根据右端点的值以及窗口内0的个数，在右端点滑动的过程中可能有三种情况：
>
> ​	1.右端点处的值为1，此时只需要将右端点继续往右滑动即可。
> ​	2.右端点处的值为0且窗口内0的个数小于K个，此时将窗口右端点往右滑动，窗口内0的个数加1。
> ​	3.右端点处的值为0且窗口内的0的个数等于K个，此时先将目前窗口的长度的值减一（因为右端点多出了一个0）作为满足题意的子数组长度的极大值来更新最大值，然后左端点向右滑动直到将原有的一个0滑出窗口。
>
> 最后，由于**存在某次滑动后窗口内的0的个数始终小于等于K直到数组结束**这种情况，因此在滑动结束后还需要将当前窗口的长度作为一个极大值，去更新整体的最大值。
>
> 特例：
>
> - [1,0,0,0]，k = 4，要输出4
> - [1,1,1,0,0,0,1,1,1,1]，k = 0，要输出4




```java
class Solution {
    public int longestOnes(int[] nums, int k) {
        int left = 0;
        int countZero = 0;
        int maxLen = Integer.MIN_VALUE;
        for(int right = 0;right<nums.length;right++){
            if(nums[right] == 1){
                continue;
            }else if(nums[right] == 0 && countZero < k){
                countZero++;
            }else{
                maxLen = Math.max(maxLen,right - left);// 此时右边界的0是多出来的,所以是right - left
                while(nums[left] != 0){// 找到左边界的第一个零
                    left++;
                }
                left++;// 跳过第一个零！画个图就知道了
            }

        }
        return Math.max(maxLen,nums.length - left);
    }
}
```



#### [904. 水果成篮](https://leetcode.cn/problems/fruit-into-baskets/)

> 思路：
>
> - `0 <= fruits[i] < fruits.length`，所以用一个freq数组存每种树在窗口内出现的频次
> - 用一个count辅助记录当前窗口内果树的种类（两个篮子）
> - **技巧点**在于：右边界加入新的值后，freq[fruit[right]]会加1，所以如果加完1后freq[fruit[right]] == 1，说明是新的果树！
> - 窗口左边界收缩条件，count > 2,即窗口内果树的种类超过两种；
> - 此时 freq[fruits[left]] -= 1 -> 同时如果减为0后，count--；然后左边界右移；
> - 当count==2时 跳出while循环，此时更新长度！
>
> 

```java
class Solution {
    public int totalFruit(int[] fruits) {
        if(fruits.length <= 2){
            return fruits.length;
        }
        int[] freq = new int[fruits.length];
        int left = 0;
        int result = 0;
        int count = 0;//当前取到的水果的种类

        for(int right = 0; right < fruits.length;right++){
            freq[fruits[right]] += 1;
            if(freq[fruits[right]] == 1) count += 1;
            while(count > 2){
                freq[fruits[left]] -= 1;
                if(freq[fruits[left]] == 0) count--;
                left++;
            }
            result = Math.max(result,right-left+1);
        }
        return result;
        
    }
}
```



#### 159.至多包含两个不同字符的最长子串

 **题意**

给定一个字符串 s ，找出至多包含两个不同字符的最长子串 t 。

**样例**

```php
例 1:
输入: “eceba”
输出: 3
解释: t 是 “ece”，长度为3。

例 2:
输入: “ccaabbb”
输出: 5
解释: t 是 “aabbb”，长度为5。
```

这个题跟水果成篮一模一样

```java
public class LC159 {
    public static void main(String[] args) {
        String s = "aabbccc";
        String s1 = "eceba";
        int res = countSubstring(s1);
        System.out.println(res);
    }
    public static  int countSubstring(String s){
        if (s.length()<=2){
            return s.length();
        }
        int maxLen = 0;
        int left = 0;
        int count = 0;
        int[] charCount = new int[26];
        for (int right = 0; right < s.length(); right++) {
            char c = s.charAt(right);
            charCount[c - 'a'] += 1;
            if (charCount[c - 'a'] == 1) count++;
            while (count > 2){
                char d = s.charAt(left++);
                charCount[d - 'a'] -= 1;
                if (charCount[d - 'a'] == 0) count--;
            }
            maxLen = Math.max(maxLen,right - left + 1);
        }
        return maxLen;
    }
}
```

## 二分搜索

二分搜索讲解：https://labuladong.gitee.io/algo/di-ling-zh-bfe1b/wo-xie-le--3c789/

> - **基本的二分搜索——找一个数：**
>
> ```java
> int binarySearch(int[] nums, int target) {
>     int left = 0; 
>     int right = nums.length - 1; // 注意
> 
>     while(left <= right) {
>         int mid = left + (right - left) / 2;
>         if(nums[mid] == target)
>             return mid; 
>         else if (nums[mid] < target)
>             left = mid + 1; // 注意
>         else if (nums[mid] > target)
>             right = mid - 1; // 注意
>     }
>     return -1;
> }
> 
> ```
>
> - **寻找左边界**
>
> **找到 target 时不要立即返回，而是缩小「搜索区间」的上界 `right`**
>
> 1. 统一left = 0；right = nums.length - 1;
> 2. while (left <= right)
> 3. 在mid == target时，找左边界：right = mid - 1;找右边界：left = mid + 1;
> 4. 判断左右**是否越界**：if (left < 0 || left >= nums.length) return -1;
> 5. 判断左右边界**是否等于target**：return nums[left] == target ? left : -1;
>
> ```java
> int left_bound(int[] nums, int target) {
>     int left = 0, right = nums.length - 1;
>     // 搜索区间为 [left, right]
>     while (left <= right) {
>         int mid = left + (right - left) / 2;
>         if (nums[mid] < target) {
>             // 搜索区间变为 [mid+1, right]
>             left = mid + 1;
>         } else if (nums[mid] > target) {
>             // 搜索区间变为 [left, mid-1]
>             right = mid - 1;
>         } else if (nums[mid] == target) {
>             // 收缩右侧边界
>             right = mid - 1;
>         }
>     }
>     // 判断 target 是否存在于 nums 中
>     // 如果越界，target 肯定不存在，返回 -1
>     if (left < 0 || left >= nums.length) {
>         return -1;
>     }
>     // 判断一下 nums[left] 是不是 target
>     return nums[left] == target ? left : -1;
> }
> ```
>
> - **寻找右边界**
>
> ```java
> int right_bound(int[] nums, int target) {
>     int left = 0, right = nums.length - 1;
>     while (left <= right) {
>         int mid = left + (right - left) / 2;
>         if (nums[mid] < target) {
>             left = mid + 1;
>         } else if (nums[mid] > target) {
>             right = mid - 1;
>         } else if (nums[mid] == target) {
>             // 这里改成收缩左侧边界即可
>             left = mid + 1;
>         }
>     }
>     if (right < 0 || right >= nums.length) {
>         return -1;
>     }
>     return nums[right] == target ? right : -1;
> }
> 
> ```
>
> 

#### [34. 在排序数组中查找元素的第一个和最后一个位置](https://leetcode.cn/problems/find-first-and-last-position-of-element-in-sorted-array/)

![image-20231005213840661](https://maekdowm-wbb.oss-cn-hangzhou.aliyuncs.com/img/image-20231005213840661.png)



#### [875. 爱吃香蕉的珂珂](https://leetcode.cn/problems/koko-eating-bananas/)

![image-20231005224307489](https://maekdowm-wbb.oss-cn-hangzhou.aliyuncs.com/img/image-20231005224307489.png)

二分搜索的套路比较固定，如果遇到一个算法问题，能够确定 `x, f(x), target` 分别是什么，并写出单调函数 `f` 的代码，那么就可以运用二分搜索的思路求解。

这题珂珂吃香蕉的速度 `K` 就是自变量 `x`，吃完所有香蕉所需的时间就是单调函数 `f(x)`，`target` 就是吃香蕉的时间限制 `H`。我们需要调整 `x`，使得 `f(x)` 尽可能接近 `target`，也就是说，我们需要找到最小的 `x`，使得 `f(x) <= target`。

它们的关系如下图：

![img](https://labuladong.github.io/pictures/二分运用/4.jpeg)

```java
piles.length <= h <= 10^9
class Solution {
    public int minEatingSpeed(int[] piles, int H) {
        int left = 1;
        int right = 1000000000 + 1;

        while (left < right) {
            int mid = left + (right - left) / 2;
            if (f(piles, mid) <= H) {
                right = mid;
            } else {
                left = mid + 1;
            }
        }
        return left;
    }

    // 定义：速度为 x 时，需要 f(x) 小时吃完所有香蕉
    // f(x) 随着 x 的增加单调递减
    int f(int[] piles, int x) {
        int hours = 0;
        for (int i = 0; i < piles.length; i++) {
            hours += piles[i] / x;
            if (piles[i] % x > 0) {
                hours++;
            }
        }
        return hours;
    }
}

```



#### [1011. 在 D 天内送达包裹的能力](https://leetcode.cn/problems/capacity-to-ship-packages-within-d-days/)

类似875

```java
class Solution {
    public int shipWithinDays(int[] weights, int days) {
        // 横坐标代表运载能力，最低为weights的最大值，最大可以是所有weight累加；
        int left = 0;
        int right = 1;
        for (int w : weights) {
            left = Math.max(left, w);
            right += w;
        }

        while (left < right) {
            int mid = left + (right - left) / 2;
            if (f(weights, mid) <= days) {
                right = mid;
            } else {
                left = mid + 1;
            }
        }

        return left;
    }

    // 定义：当运载能力为 x 时，需要 f(x) 天运完所有货物
    // f(x) 随着 x 的增加单调递减
    int f(int[] weights, int x) {
        int days = 0;
        for (int i = 0; i < weights.length; ) {
            // 尽可能多装货物
            int cap = x;
            while (i < weights.length) {
                if (cap < weights[i]) break;
                else cap -= weights[i];
                i++;
            }
            days++;
        }
        return days;
    }
}

```



## 排序（重写sort）

```java
public class Sort {
    public static void main(String[] args) {
        //1、数组排序
        int[] arr = {12,33,44,55,2,4,66,31};
        Arrays.sort(arr);
        //2、List排序
        List<Integer> list = new ArrayList<>();
        list.add(5);
        list.add(3);
        list.add(6);
        list.add(8);
        list.add(1);
        //Collections.sort(list);// List<String>也可以直接sort
        Collections.sort(list,((o1, o2) -> {
            return o1 - o2;//从小到大
        }));
//        for (Integer integer : list) {
//            System.out.println(integer);
//        }
        //3、TreeMap排序——默认以key升序排序
        Map<String,String> map = new TreeMap<>(new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                return o1.compareTo(o2);
            }
        });
        map.put("c","cccc");
        map.put("a","accc");
        map.put("d","dccc");
        map.put("b","bccc");
        for (Map.Entry<String, String> entry : map.entrySet()) {
            System.out.println(entry.getKey());
        }
        //TreeMap对value排序，需要借助Collections.sort
        Map<String,String> map2 = new TreeMap<>();
        map2.put("c","cccc");
        map2.put("a","accc");
        map2.put("d","dccc");
        map2.put("b","bccc");
        ArrayList<Map.Entry<String, String>> entries = new ArrayList<>(map2.entrySet());
        entries.sort(((o1, o2) -> o2.getValue().compareTo(o1.getValue())));
        //可简写为Collections.sort(entries,(Comparator.comparing(Map.Entry::getValue)));
        for (Map.Entry<String, String> entry : entries) {
            System.out.println(entry.getKey() + ":" + entry.getValue());
        }
        //Hashmap同上
    }
}
```

#### [1030. 距离顺序排列矩阵单元格](https://leetcode.cn/problems/matrix-cells-in-distance-order/)

常规的比较器

```java
class Solution {
    public int[][] allCellsDistOrder(int rows, int cols, int rCenter, int cCenter) {
        ArrayList<int[]> list = new ArrayList<>();
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                int[] cordinates = new int[]{i,j};
                list.add(cordinates);
            }
        }
        list.sort(Comparator.comparingInt(o -> (Math.abs(o[0] - rCenter) + Math.abs(o[1] - cCenter))));
        int[][] res = new int[list.size()][2];
        int index = 0;
        for (int[] ints : list) {
            res[index++] = ints;
        }
        return res;
    }
}
```

#### [179. 最大数](https://leetcode.cn/problems/largest-number/)

可以根据「结果」来决定a和b的排序关系:
**如果拼接结果ab要比ba好，那么我们会认为a应该放在b前面。**
另外，注意我们需要处理前导零(最多保留位)

```java
class Solution {
    public String largestNumber(int[] nums) {
        if (nums.length == 0){
            return "";
        }
        boolean isAllZero = true;
        List<String> numList = new ArrayList<>();
        for (int num : nums) {
            if (num != 0){
                isAllZero = false;
            }
            numList.add(String.valueOf(num));
        }
        if(isAllZero){
            return "0";
        }
        numList.sort((o1, o2) -> (o2 + o1).compareTo(o1 + o2));
        StringBuilder stringBuilder = new StringBuilder();
        for (String s : numList) {
            stringBuilder.append(s);
        }
        return stringBuilder.toString();
    }
}
```

#### [853. 车队](https://leetcode.cn/problems/car-fleet/)

```java
class Solution {
    public int carFleet(int target, int[] position, int[] speed) {
        int carsNum = position.length;
        if(carsNum <= 1){
            return carsNum;
        }
        double[][] cars = new double[carsNum][2];//[当前顺位，到达终点时间]
        for (int i = 0; i < carsNum; i++) {
            cars[i][0] = position[i];
            cars[i][1] = (double) (target - position[i]) / speed[i];
        }
        Arrays.sort(cars,((o1, o2) -> (int) (o1[0] - o2[0])));//[位置靠前的离终点近]
        int ans = 0;
        for (int i = carsNum - 1; i > 0; i--) {//一辆车永远不会超过前面的另一辆车 只用看相邻两车
            if (cars[i][1] < cars[i-1][1]){//前车到达时间更短，后车一定追不上！
                ans++;
            }else {//前车比后车到达时间更长，它可以追上去，并与前车 以相同的速度 紧接着行驶
                cars[i-1][1] = cars[i][1];
            }
        }
        return ans + 1;
    }
}
```



## 二叉树

#### [103. 二叉树的锯齿形层序遍历](https://leetcode.cn/problems/binary-tree-zigzag-level-order-traversal/)

与层序遍历几乎一致

```java
/**
 * Definition for a binary tree node.
 * public class TreeNode {
 *     int val;
 *     TreeNode left;
 *     TreeNode right;
 *     TreeNode() {}
 *     TreeNode(int val) { this.val = val; }
 *     TreeNode(int val, TreeNode left, TreeNode right) {
 *         this.val = val;
 *         this.left = left;
 *         this.right = right;
 *     }
 * }
 */
class Solution {
    public List<List<Integer>> zigzagLevelOrder(TreeNode root) {
        List<List<Integer>> res = new LinkedList<>();
        if(root == null){
            return res;
        }
        Queue<TreeNode> q = new LinkedList<>();
        q.offer(root);
        boolean flag = true;// 为 true 时向右，false 时向左
        while(!q.isEmpty()){
            int sz = q.size();
            LinkedList<Integer> level = new LinkedList<>();
            for(int i = 0;i<sz;i++){
                TreeNode cur = q.poll();
                if(flag){
                    level.addLast(cur.val);
                }else{
                    level.addFirst(cur.val);
                }
                if(cur.left != null){
                    q.offer(cur.left);
                }
                if(cur.right != null){
                    q.offer(cur.right);
                }
            }
            flag = !flag;//修改方向
            res.add(level);
        }
        return res;
    }
}
```

#### [112. 路径总和](https://leetcode.cn/problems/path-sum/)

```jade
class Solution {
    public boolean hasPathSum(TreeNode root, int targetSum) {
        if(root == null){
            return false;
        }
        targetSum -= root.val;
        if(root.left == null && root.right == null){//到叶子节点了
            return targetSum == 0;
        }
        if(root.left != null){
            boolean left = hasPathSum(root.left,targetSum);
            if(left) return true;
        }
        if(root.right != null){
            boolean right = hasPathSum(root.right,targetSum);
            if(right) return true;
        }
        return false;
    }
}
```

## 回溯

#### 基本框架

```java
result = []
def backtrack(路径, 选择列表):
    if 满足结束条件:
        result.add(路径)
        return
    
    for 选择 in 选择列表:
		会有添加剪纸的操作（如排列中有重复元素）
        做选择
        backtrack(路径, 选择列表)
        撤销选择

```

#### [46. 全排列](https://leetcode.cn/problems/permutations/)

典型的回溯模板；

```java
class Solution {
    List<List<Integer>> res = new LinkedList<>();
    /* 主函数，输入一组不重复的数字，返回它们的全排列 */
    List<List<Integer>> permute(int[] nums) {
        // 记录「路径」
        LinkedList<Integer> track = new LinkedList<>();
        // 「路径」中的元素会被标记为 true，避免重复使用
        boolean[] used = new boolean[nums.length];        
        backtrack(nums, track, used);
        return res;
    }

    // 路径：记录在 track 中
    // 选择列表：nums 中不存在于 track 的那些元素（used[i] 为 false）
    // 结束条件：nums 中的元素全都在 track 中出现
    void backtrack(int[] nums, LinkedList<Integer> track, boolean[] used) {
        // 触发结束条件
        if (track.size() == nums.length) {
            res.add(new LinkedList(track));
            return;
        }
        for (int i = 0; i < nums.length; i++) {
            // 排除不合法的选择
            if (used[i]) {
                // nums[i] 已经在 track 中，跳过
                continue;
            }
            // 做选择
            track.add(nums[i]);
            used[i] = true;
            // 进入下一层决策树
            backtrack(nums, track, used);
            // 取消选择
            track.removeLast();
            used[i] = false;
        }
    }
}
```

####  [78. 子集](https://leetcode.cn/problems/subsets/)

```java
class Solution {
    List<List<Integer>> res = new LinkedList<>();
    public List<List<Integer>> subsets(int[] nums) {
        LinkedList<Integer> path = new LinkedList<>();
        backTrack(nums,0,path);
        return res;
    }
    public void backTrack(int[] nums, int start,LinkedList<Integer> path){
        res.add(new LinkedList(path));
        for(int i = start;i<nums.length;i++){
            path.add(nums[i]);
            backTrack(nums,i+1,path);
            path.removeLast();
        }
    }
}
```

#### [77. 组合](https://leetcode.cn/problems/combinations/)

```java
class Solution {
    List<List<Integer>> res = new LinkedList<>();
    public List<List<Integer>> combine(int n, int k) {
        LinkedList<Integer> path = new LinkedList<>();
        backTrack(n,k,1,path);
        return res;

    }
     public void backTrack(int n,int k, int start,LinkedList<Integer> path){
         if(path.size() == k){
             res.add(new LinkedList(path));
         }
         for(int i = start;i<=n;i++){
             path.add(i);
             backTrack(n,k,i+1,path);
             path.removeLast();
         }
     }
}
```

#### [17. 电话号码的字母组合](https://leetcode.cn/problems/letter-combinations-of-a-phone-number/)

此题为组合模板

```java
class Solution {
    String[] mapping = new String[] {
            "", "", "abc", "def", "ghi", "jkl", "mno", "pqrs", "tuv", "wxyz"
    };
    List<String> res = new LinkedList<>();
    public List<String> letterCombinations(String digits) {
        if(digits.isEmpty()) return res;
        backTrack(digits,0,new StringBuilder());
        return res;
    }
    public void backTrack(String digits,int start,StringBuilder sb){
        if (sb.length() == digits.length()){
            res.add(sb.toString());
            return;
        }
        for (int i = start; i < digits.length(); i++) {
            int digit = digits.charAt(i) - '0';
            for (char c : mapping[digit].toCharArray()) {
                sb.append(c);
                backTrack(digits,i+1,sb);
                sb.deleteCharAt(sb.length()-1);
            }
        }
    }
}
```

#### [131. 分割回文串](https://leetcode.cn/problems/palindrome-partitioning/)

只有树枝是回文串的时候才会继续往下走，终止条件为走到叶子节点！

<img src="https://labuladong.github.io/pictures/%E7%9F%AD%E9%A2%98%E8%A7%A3/131.jpeg" alt="img" style="zoom: 25%;" />

```java
class Solution {
    List<List<String>> res = new LinkedList<>();
    LinkedList<String> track = new LinkedList<>();

    public List<List<String>> partition(String s) {
        backtrack(s, 0);
        return res;
    }

    // 回溯算法框架
    void backtrack(String s, int start) {
        if (start == s.length()) {
            // base case，走到叶子节点
            // 即整个 s 被成功分割为若干个回文子串，记下答案
            res.add(new ArrayList<String>(track));
        }
        for (int i = start; i < s.length(); i++) {
            if (!isPalindrome(s, start, i)) {
                // s[start..i] 不是回文串，不能分割
                continue;
            }
            // s[start..i] 是一个回文串，可以进行分割
            // 做选择，把 s[start..i] 放入路径列表中
            track.addLast(s.substring(start, i + 1));
            // 进入回溯树的下一层，继续切分 s[i+1..]
            backtrack(s, i + 1);
            // 撤销选择
            track.removeLast();
        }
    }

    // 用双指针技巧判断 s[lo..hi] 是否是一个回文串
    boolean isPalindrome(String s, int lo, int hi) {
        while (lo < hi) {
            if (s.charAt(lo) != s.charAt(hi)) {
                return false;
            }
            lo++;
            hi--;
        }
        return true;
    }
}
```

#### [93. 复原 IP 地址](https://leetcode.cn/problems/restore-ip-addresses/)

跟上一题基本框架一样，仅isValid函数有些许不同；

```java
class Solution {

    List<String> res = new LinkedList<>();
    LinkedList<String> track = new LinkedList<>();

    public List<String> restoreIpAddresses(String s) {
        backtrack(s, 0);
        return res;
    }

    // 回溯算法框架
    void backtrack(String s, int start) {
        if (start == s.length() && track.size() == 4) {
            // base case，走到叶子节点
            // 即整个 s 被成功分割为合法的四部分，记下答案
            res.add(String.join(".", track));
        }
        for (int i = start; i < s.length(); i++) {
            if (!isValid(s, start, i)) {
                // s[start..i] 不是合法的 ip 数字，不能分割
                continue;
            }
            if (track.size() >= 4) {
                // 已经分解成 4 部分了，不能再分解了
                break;
            }
            // s[start..i] 是一个合法的 ip 数字，可以进行分割
            // 做选择，把 s[start..i] 放入路径列表中
            track.addLast(s.substring(start, i + 1));
            // 进入回溯树的下一层，继续切分 s[i+1..]
            backtrack(s, i + 1);
            // 撤销选择
            track.removeLast();
        }
    }

    // 判断 s[
    boolean isValid(String s, int start, int end) {
        int length = end - start + 1;

        if (length == 0 || length > 3) {
            return false;
        }

        if (length == 1) {
            // 如果只有一位数字，肯定是合法的
            return true;
        }

        if (s.charAt(start) == '0') {
            // 多于一位数字，但开头是 0，肯定不合法
            return false;
        }

        if (length <= 2) {
            // 排除了开头是 0 的情况，那么如果是两位数，怎么着都是合法的
            return true;
        }

        // 现在输入的一定是三位数
        if (Integer.parseInt(s.substring(start, start + length)) > 255) {
            // 不可能大于 255
            return false;
        } else {
            return true;
        }

    }
}
```

## BFS

#### 基本框架

**问题的本质就是让你在一幅「图」中找到从起点 `start` 到终点 `target` 的最近距离**

![img](https://labuladong.gitee.io/algo/images/dijkstra/1.jpeg)

```java
// 计算从起点 start 到终点 target 的最近距离
int BFS(Node start, Node target) {
    Queue<Node> q; // 核心数据结构
    Set<Node> visited; // 避免走回头路
    
    q.offer(start); // 将起点加入队列
    visited.add(start);

    while (q not empty) {
        int sz = q.size();
        /* 将当前队列中的所有节点向四周扩散 */
        for (int i = 0; i < sz; i++) {
            Node cur = q.poll();
            /* 划重点：这里判断是否到达终点 */
            if (cur is target)
                return step;
            /* 将 cur 的相邻节点加入队列 */
            for (Node x : cur.adj()) {
                if (x not in visited) {
                    q.offer(x);
                    visited.add(x);
                }
            }
        }
    }
    // 如果走到这里，说明在图中没有找到目标节点
}
```

#### [111. 二叉树的最小深度](https://leetcode.cn/problems/minimum-depth-of-binary-tree/)

二叉树没有从子节点回父节点的路径，不需要记录visited

```java
class Solution {
    public int minDepth(TreeNode root) {
        if (root == null) return 0;
        Queue<TreeNode> q = new LinkedList<>();
        q.offer(root);
        int depth = 1;
        while (!q.isEmpty()) {
            int size = q.size();
            for (int i = 0; i < size; i++) {
                TreeNode cur = q.poll();
                if (cur.left == null && cur.right == null) {
                    return depth;
                }
                if (cur.left != null) {
                    q.offer(cur.left);
                }
                if (cur.right != null) {
                    q.offer(cur.right);
                }
            }
            depth++;
        }
        return depth;
    }
}
```

#### [752. 打开转盘锁](https://leetcode.cn/problems/open-the-lock/)

```java
class Solution {
    public int openLock(String[] deadends, String target) {
        // 记录需要跳过的死亡密码
        Set<String> deads = new HashSet<>();
        for (String s : deadends) deads.add(s);
        // 记录已经穷举过的密码，防止走回头路
        Set<String> visited = new HashSet<>();
        Queue<String> q = new LinkedList<>();
        // 从起点开始启动广度优先搜索
        int step = 0;
        q.offer("0000");
        visited.add("0000");

        while (!q.isEmpty()) {
            int sz = q.size();
            /* 将当前队列中的所有节点向周围扩散 */
            for (int i = 0; i < sz; i++) {
                String cur = q.poll();

                /* 判断是否到达终点 */
                if (deads.contains(cur))
                    continue;
                if (cur.equals(target))
                    return step;

                /* 将一个节点的未遍历相邻节点加入队列 */
                for (int j = 0; j < 4; j++) {
                    String up = plusOne(cur, j);
                    if (!visited.contains(up)) {
                        q.offer(up);
                        visited.add(up);
                    }
                    String down = minusOne(cur, j);
                    if (!visited.contains(down)) {
                        q.offer(down);
                        visited.add(down);
                    }
                }
            }
            /* 在这里增加步数 */
            step++;
        }
        // 如果穷举完都没找到目标密码，那就是找不到了
        return -1;
    }

    // 将 s[j] 向上拨动一次
    String plusOne(String s, int j) {
        char[] ch = s.toCharArray();
        if (ch[j] == '9')
            ch[j] = '0';
        else
            ch[j] += 1;
        return new String(ch);
    }

    // 将 s[i] 向下拨动一次
    String minusOne(String s, int j) {
        char[] ch = s.toCharArray();
        if (ch[j] == '0')
            ch[j] = '9';
        else
            ch[j] -= 1;
        return new String(ch);
    }
}
// 详细解析参见：
// https://labuladong.github.io/article/?qno=752

```



## 优先队列
#### [218. 天际线问题](https://leetcode.cn/problems/the-skyline-problem/)

![image-20231005184052285](https://maekdowm-wbb.oss-cn-hangzhou.aliyuncs.com/img/image-20231005184052285.png)

![image-20231005184605634](https://maekdowm-wbb.oss-cn-hangzhou.aliyuncs.com/img/image-20231005184605634.png)
