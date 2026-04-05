# AMSI_machine_learning_project

針對 **AMSI（Antimalware Scan Interface）Bypass 攻擊手法**的機器學習偵測系統 。目標是訓練分類器，從 PowerShell/CMD 指令的靜態特徵中自動識別惡意 AMSI 繞過 payload，並同時評估傳統 Regex 簽名規則的覆蓋缺口 。 
AMSI bypass 分析研究，由 LLM 進行資料搜集成資料集，並且分析

- `AMSI_Bypass_ML_Dataset.xlsx` -> 涵蓋各種 AMSI 攻擊資訊的資料
- 正常行為 cmdline 於 `amsi_ml_pipline.py` 內

## 資料集設計
資料集分為兩類，合計約 **144 筆樣本** ：
| 類別 | 樣本數 | 來源 |
|------|--------|------|
| Benign（正常指令） | ~119 筆 | 手工建立的正常 PS/CMD 指令（系統管理、網路診斷等） |
| AMSI Bypass（惡意） | ~25 筆 | 從 `Payload_Samples` Excel 工作表讀取的真實 bypass payload |

資料集規模偏小，這是後續分析需注意的重要限制 。

## 特徵工程（Feature Engineering）

- **文字統計**：`code_length`、`entropy`（Shannon 熵值）、`line_count`、`special_char_ratio`
- **AMSI 關鍵字**：`amsi_keyword_count`、`has_amsi_keyword`（偵測 `AmsiUtils`、`amsiInitFailed` 等）
- **Win32 API**：`has_virtualprotect`、`has_getprocaddress`、`has_loadlibrary` 等記憶體操作 API
- **混淆指標**：backtick 計數、base64 特徵、char cast 次數、字串拼接密度
- **進階手法**：`has_hw_breakpoint`（硬體斷點繞過）、`has_etw_tamper`（ETW 竄改）、`has_scriptblock_ast`（ScriptBlock AST 注入）、`has_clr_targeting`
- **綜合風險分數 `composite_risk`**：加權累加各高危特徵，memory patch 和 hw_breakpoint 各佔最高權重（×5） 

## 模型效能分析
所有模型均以 **5-Fold Stratified Cross-Validation** 評估，結果非常亮眼 ：

| 模型 | Accuracy | F1 | Precision | Recall |
|------|----------|----|-----------|--------|
| Random Forest | 0.99 | 1.00 | 1.00 | **0.66** |
| XGBoost | 0.99 | 1.00 | 0.96 | 0.92 |
| Logistic Regression | 0.99 | 1.00 | 0.96 | 0.92 |
| SVM (RBF) | 0.98 | 0.95 | 1.00 | 0.91 |
| Gradient Boosting | 0.99 | 0.99 | 0.96 | 0.92 |

**Random Forest 的 Recall 僅 0.66** 是最值得注意的結果——代表在 CV 切分下，它漏掉了約 **34% 的 AMSI bypass** 。這不是模型弱，而是因為樣本數太少（25 筆惡意樣本），在 5-fold 切分後每折的訓練樣本更稀少，導致樹狀模型泛化能力下降。XGBoost 和 Logistic Regression 的 Recall=0.92 表現更穩健 。
**Confusion Matrix（RF 全資料訓練）**顯示 119 Benign + 25 Malicious 全部正確分類（0 FP, 0 FN），但這是 in-sample 評估，存在過擬合疑慮 。 

## 特徵重要性解讀
**Random Forest** 最看重的特徵依序為：`code_length`（~0.27）→ `composite_risk`（~0.20）→ `entropy`（~0.12）→ `line_count` 。這代表 RF 傾向依賴**文字長度與複雜度**來區分類別。 
**XGBoost** 的排序則完全不同：`composite_risk`（~0.55）→ `code_length`（~0.43），其他特徵幾乎可忽略 。這顯示 XGBoost 認為人工設計的 `composite_risk` 分數已高度濃縮了惡意特徵，是最具區別力的單一指標。

## ROC 與 PR 曲線
- **Random Forest AUC = 1.000**，SVM AUC = 0.998，表現最佳 
- XGBoost 和 Gradient Boosting AUC = 0.960，Logistic Regression AUC = 0.968 
PR 曲線（Precision-Recall）全部 AUC = 1.000，但這是在**全訓練資料**上計算，並非 CV，解讀時需保守 。 

## 偵測簽名覆蓋率分析
這是整個專案最具實戰價值的部分 ：
- **Per-Signature 分析**：SIG-007、SIG-009、SIG-010、SIG-012、SIG-017、SIG-018 的 Recall 幾乎為 0，代表這些規則**完全沒有命中任何惡意 payload** 
- **Per-Payload 分析**：PL-002 和 PL-005 被 2 條簽名命中，但 PL-006、PL-008 至 PL-010、PL-013 至 PL-017、PL-019 至 PL-025 等**大量 payload 被 0 條規則命中**，屬於完全的偵測盲區
- Precision 普遍為 1.0 代表簽名命中時幾乎沒有誤報，但 Recall 低意味著很多 bypass 手法根本逃過了 Regex 規則

## EDA 資料探索分析
四張子圖揭示了資料本質：

1. **Top 15 判別特徵**：`composite_risk` 的 Malicious Mean 遠超 Benign（約 13 vs 0），是最強的分離特徵 
2. **Composite Risk 分佈**：Benign 樣本幾乎全部集中在 score=0，Malicious 則分散在 5–27 之間，虛線標示的 threshold=5 可作為簡單規則觸發點
3. **Shannon Entropy**：Benign 集中於 3.5–4.5 之間；Malicious 偏高（4.5–5.5），反映混淆程式碼的隨機性更高 
4. **Binary Feature 比率**：Malicious 中 `has_amsi_keyword` 約 65%、`virtualprotect` 約 35%、`reflection` 約 28%，而 Benign 樣本這些特徵幾乎為零
 
![image](https://raw.githubusercontent.com/jonafk555/AMSI_machine_learning_project/refs/heads/main/amsi_coverage_analysis.png)
<img width="2683" height="2065" alt="image" src="https://github.com/user-attachments/assets/3923a43a-630e-48a4-b7e0-63c0d4500847" />
<img width="2683" height="2063" alt="image" src="https://github.com/user-attachments/assets/19576a71-e700-4008-a7d4-d0f2fff33e50" />
<img width="2384" height="887" alt="image" src="https://github.com/user-attachments/assets/61533560-426f-495f-8e30-bd96bf8e370b" />


