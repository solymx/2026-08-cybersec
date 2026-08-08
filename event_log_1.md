# Q
As a security Analyst, you need to provide the details of the attack executed by the Red team, based on these relevant Windows events. Analyze them and determine which specific MITRE ATT&CK technique and sub-technique were used. Please provide your answer in the following format T1000.001.

# A

答案：T1110.003

（Brute Force: Password Spraying — 暴力破解之密碼噴灑）

---

這份 EVTX 共 3,232 筆事件（DC：WIN-VUL8GK5R197.globex.int，網域 GLOBEX.INT）。
大部分是 DC 升級與稽核設定的背景雜訊（4907、4624/4634/4672、4731/4735 等由 ANONYMOUS LOGON 產生的 dcpromo 內建群組建立）。
真正的紅隊行為集中在 2023-01-20 20:46 ~ 20:52。



關鍵事件對：4648（使用明確認證登入）→ 4625（登入失敗）


判讀為「噴灑」而非「猜測」的四個依據
1. 橫向掃帳號，不縱向試密碼 — 每一輪都是對 Administrator、Guest、sec598、krbtgt 各嘗試一次，然後換下一輪。若是 T1110.001 密碼猜測，會看到同一帳號連續多次失敗；這裡完全相反：一個密碼掃過所有帳號。
2. 輪次之間有間隔 — 20:46 → 20:51 → 20:51，刻意拉開節奏，典型是為了避開帳號鎖定原則（lockout threshold）。
3. 每筆 4625 前都有一筆 4648 — SubjectUserName: sec598 以「明確認證」方式輪流帶入不同 TargetUserName。這是工具化行為（如 Spray-Passwords.ps1、DomainPasswordSpray、CrackMapExec），不是人工登入。
4. 子狀態碼洩漏帳號狀態 — Administrator / sec598 / krbtgt 回 0xC000006A（密碼錯誤，帳號存在），Guest 回 0xC0000072（帳號已停用）。攻擊者藉此同時完成帳號有效性驗證。
