# AMSI Bypass Detection — ML 分析報告

## 1. 資料集概述
| 項目 | 數量 |
|------|------|
| 惡意 Payload (AMSI Bypass) | 25 |
| 正常指令 (Benign) | 119 |
| 總樣本數 | 144 |
| 萃取特徵數 | 34 |
| 偵測規則數 | 19 |

## 2. 模型效能比較 (5-Fold Stratified CV)
| Model | Accuracy | F1-Score | Precision | Recall |
|-------|----------|----------|-----------|--------|
| Random Forest | 0.9931 | 0.9778 | 1.0000 | 0.9600 |
| XGBoost | 0.9860 | 0.9556 | 1.0000 | 0.9200 |
| Logistic Regression | 0.9860 | 0.9556 | 1.0000 | 0.9200 |
| SVM (RBF) | 0.9793 | 0.9485 | 0.9095 | 1.0000 |
| Gradient Boosting | 0.9860 | 0.9556 | 1.0000 | 0.9200 |

**最佳模型**: Random Forest (F1=0.9778)

## 3. 最重要的偵測特徵 (Random Forest Top 10)
| Rank | Feature | Importance |
|------|---------|------------|
| 1 | code_length | 0.2672 |
| 2 | composite_risk | 0.1975 |
| 3 | entropy | 0.1186 |
| 4 | line_count | 0.0912 |
| 5 | amsi_keyword_count | 0.0561 |
| 6 | has_amsi_keyword | 0.0461 |
| 7 | avg_line_length | 0.0392 |
| 8 | special_char_ratio | 0.0313 |
| 9 | plus_operator_density | 0.0306 |
| 10 | has_ps_downgrade | 0.0189 |

## 4. 偵測規則覆蓋率
- 綜合覆蓋率: **13/25 (52.0%)**

### 偵測缺口 (未被任何 Regex 規則覆蓋的 Payload)
- **PL-006**: AmsiScanBuffer Patch - Classic (Rasta Mouse)
- **PL-008**: AmsiScanString RDX Zero Patch (CyberArk)
- **PL-009**: AmsiOpenSession RET Patch
- **PL-010**: String Concatenation Bypass
- **PL-013**: AMSI Provider Registry Removal
- **PL-016**: CLR.dll AmsiScanBuffer String Modification
- **PL-017**: Hardware Breakpoint VEH Patchless Bypass
- **PL-019**: TrollAMSI Reflection Method Swap
- **PL-021**: AmsiScanBuffer Length Zero Patch
- **PL-023**: Disable ScriptBlock Logging via Reflection
- **PL-024**: AmsiTrigger Targeted Obfuscation Workflow
- **PL-025**: VBA Macro AMSI Bypass (Office)

## 5. TF-IDF 文字分析
- TF-IDF + Random Forest F1: **0.7778**
- 最具區別力的 AMSI Bypass Token: amsi, patch, static, ref, amsiscanbuffer, null, using, virtualprotect, address, assembly.gettype

## 6. 建議
1. **高風險特徵組合**: composite_risk > 5 的指令應標記為可疑
2. **偵測缺口補強**: 針對未覆蓋的 Payload 類型開發新偵測規則
3. **特徵擴充**: 加入 call stack 分析、parent-child process 關係、時間序列行為特徵
4. **模型部署**: 建議使用 XGBoost/RF 作為第一層快篩, SVM 作為第二層確認
5. **持續更新**: 定期加入新的 bypass 樣本與正常指令擴充訓練集

## 7. 產出檔案
- `amsi_features_dataset.csv` — 完整特徵資料集 (可直接用於 ML 訓練)
- `amsi_signature_coverage.csv` — 偵測規則覆蓋率矩陣
- `amsi_eda_analysis.png` — 探索式資料分析圖表
- `amsi_model_performance.png` — 模型效能與特徵重要性
- `amsi_roc_pr_curves.png` — ROC & Precision-Recall 曲線
- `amsi_coverage_analysis.png` — 偵測規則覆蓋率分析
