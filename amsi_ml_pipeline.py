#!/usr/bin/env python3
"""
=============================================================================
AMSI Bypass Detection — ML Analysis Pipeline
=============================================================================
Purpose:
  1. 建立正常 PowerShell/CMD 指令的 Benign 資料集 (ground truth)
  2. 從 Payload_Samples 萃取特徵 (Feature Engineering)
  3. 訓練多種分類器 (Random Forest, XGBoost, SVM, Logistic Regression)
  4. 評估模型效能 (Confusion Matrix, ROC, Classification Report)
  5. 分析 Detection_Signatures 覆蓋率 (Coverage Gap Analysis)
  6. 輸出完整分析報告與視覺化圖表

Author: Security Research ML Pipeline
Date: 2026-04
=============================================================================
"""

import pandas as pd
import numpy as np
import re
import os
import warnings
import json
from collections import Counter

# ML
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    precision_recall_curve, f1_score, accuracy_score
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

# Visualization
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings('ignore')
np.random.seed(42)

OUTPUT_DIR = '/mnt/user-data/outputs'
DATASET_PATH = os.path.join(OUTPUT_DIR, 'AMSI_Bypass_ML_Dataset.xlsx')

# =============================================================================
# SECTION 1: 建立 Benign PowerShell/CMD 資料集
# =============================================================================
print("=" * 70)
print("SECTION 1: 建立 Benign 基準資料集 (正常系統管理指令)")
print("=" * 70)

benign_commands = [
    # --- 系統管理 ---
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
    "Get-Service | Where-Object {$_.Status -eq 'Running'}",
    "Get-EventLog -LogName System -Newest 50",
    "Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version",
    "Get-ComputerInfo | Select-Object WindowsProductName, OsArchitecture",
    "systeminfo | findstr /B /C:'OS Name' /C:'OS Version'",
    "Get-ChildItem C:\\Windows\\System32 -Filter *.dll | Measure-Object",
    "Get-HotFix | Sort-Object InstalledOn -Descending",
    "Get-Disk | Select-Object Number, FriendlyName, Size, HealthStatus",
    "Get-NetAdapter | Select-Object Name, Status, LinkSpeed",
    # --- 使用者管理 ---
    "Get-LocalUser | Select-Object Name, Enabled, LastLogon",
    "Get-LocalGroup | Select-Object Name, Description",
    "Get-LocalGroupMember -Group 'Administrators'",
    "whoami /priv",
    "net user",
    "net localgroup administrators",
    "Get-ADUser -Filter * -Properties LastLogonDate | Select Name, LastLogonDate",
    # --- 檔案操作 ---
    "Get-ChildItem -Path C:\\Users -Recurse -Filter *.log | Select FullName, Length",
    "Copy-Item -Path C:\\temp\\config.xml -Destination C:\\backup\\",
    "Remove-Item -Path C:\\temp\\*.tmp -Force",
    "New-Item -ItemType Directory -Path C:\\Projects\\NewFolder",
    "Compress-Archive -Path C:\\Logs -DestinationPath C:\\Archives\\logs.zip",
    "Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts",
    "Test-Path C:\\Windows\\System32\\cmd.exe",
    "Get-FileHash C:\\Windows\\System32\\notepad.exe -Algorithm SHA256",
    "Get-Acl C:\\Windows\\System32 | Format-List",
    # --- 網路診斷 ---
    "Test-NetConnection -ComputerName google.com -Port 443",
    "Resolve-DnsName google.com",
    "Get-NetTCPConnection | Where-Object State -eq 'Established'",
    "Get-NetIPConfiguration",
    "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Select DisplayName",
    "ping -n 4 8.8.8.8",
    "tracert google.com",
    "nslookup microsoft.com",
    "netstat -ano | findstr ESTABLISHED",
    "ipconfig /all",
    "arp -a",
    # --- 效能監控 ---
    "Get-Counter '\\Processor(_Total)\\% Processor Time' -SampleInterval 2 -MaxSamples 5",
    "Get-Process | Where-Object {$_.WorkingSet64 -gt 100MB} | Select Name, WorkingSet64",
    "Get-CimInstance Win32_LogicalDisk | Select DeviceID, FreeSpace, Size",
    "Get-Counter '\\Memory\\Available MBytes'",
    # --- 排程與服務 ---
    "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select TaskName",
    "Start-Service -Name 'Spooler'",
    "Stop-Service -Name 'Spooler' -Force",
    "Restart-Service -Name 'wuauserv'",
    "Set-Service -Name 'Spooler' -StartupType Automatic",
    # --- 日誌與稽核 ---
    "Get-WinEvent -LogName Security -MaxEvents 100",
    "Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 20",
    "wevtutil qe Security /c:10 /f:text",
    # --- PowerShell 管理 ---
    "Get-Module -ListAvailable | Select Name, Version",
    "Get-Command -Module Microsoft.PowerShell.Management",
    "Get-ExecutionPolicy -List",
    "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser",
    "$PSVersionTable",
    "Get-Help Get-Process -Full",
    "Update-Help -Force -ErrorAction SilentlyContinue",
    # --- 一般 CMD ---
    "dir C:\\Windows\\System32 /s /b | find \".exe\"",
    "type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "tasklist /svc",
    "schtasks /query /fo LIST",
    "wmic process list brief",
    "assoc .txt",
    "ftype txtfile",
    "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "certutil -hashfile C:\\file.txt SHA256",
    # --- 開發/IT維運 ---
    "Import-Module ActiveDirectory",
    "Get-ADComputer -Filter * | Select Name, OperatingSystem",
    "Test-WSMan -ComputerName server01",
    "Enter-PSSession -ComputerName server01 -Credential (Get-Credential)",
    "Invoke-Command -ComputerName server01 -ScriptBlock {Get-Process}",
    "Get-DnsClientServerAddress",
    "Get-WindowsFeature | Where-Object {$_.Installed -eq $true}",
    "Install-WindowsFeature -Name Web-Server",
    # --- 安全性相關(正常操作) ---
    "Get-MpComputerStatus",
    "Update-MpSignature",
    "Get-MpThreatDetection",
    "Get-BitLockerVolume",
    "Get-Tpm",
    "gpresult /r",
    "secedit /export /cfg C:\\temp\\secpol.cfg",
    "Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections",
    # --- 套件管理 ---
    "Install-Module -Name PSReadLine -Force",
    "Find-Module -Name Az*",
    "Get-InstalledModule",
    "choco list --local-only",
    "winget list",
    # --- Docker/容器 ---
    "docker ps -a",
    "docker images",
    "kubectl get pods --all-namespaces",
    # --- Git ---
    "git status",
    "git log --oneline -10",
    "git branch -a",
    # --- 系統資訊 ---
    "Get-CimInstance -ClassName Win32_BIOS",
    "Get-CimInstance -ClassName Win32_Processor | Select Name, NumberOfCores",
    "Get-PhysicalDisk | Select MediaType, Size, HealthStatus",
    "[System.Environment]::OSVersion",
    "[System.DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')",
    "Get-TimeZone",
    "Get-Culture",
    # --- 簡單算術/字串(非惡意) ---
    "$x = 1 + 2 + 3; Write-Output $x",
    "'Hello World'.ToUpper()",
    "[math]::Sqrt(144)",
    "1..10 | ForEach-Object { $_ * 2 }",
    "(Get-Date).AddDays(-7)",
    "Write-Host 'System check complete' -ForegroundColor Green",
    "Read-Host 'Enter your name'",
    "$env:COMPUTERNAME",
    "$env:USERNAME",
    "$env:PATH -split ';'",
    # --- 正常 .NET 使用(非惡意) ---
    "[System.Net.Dns]::GetHostEntry('localhost')",
    "[System.IO.Path]::GetTempPath()",
    "[System.Guid]::NewGuid()",
    "[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('test'))",
    "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('dGVzdA=='))",
    "[System.Reflection.Assembly]::GetExecutingAssembly()",  # 正常反射用法
    "[System.IO.File]::ReadAllText('C:\\temp\\config.json')",
    "New-Object System.Net.WebClient",  # 正常用法(非下載 payload)
    "[System.Math]::Round(3.14159, 2)",
    "[System.Environment]::MachineName",
]

print(f"  建立 {len(benign_commands)} 筆正常指令作為 Benign 基準")

# =============================================================================
# SECTION 2: Feature Engineering
# =============================================================================
print("\n" + "=" * 70)
print("SECTION 2: 特徵工程 (Feature Engineering)")
print("=" * 70)

def extract_features(code_str):
    """從指令/payload 文字萃取結構化特徵"""
    if not isinstance(code_str, str):
        code_str = str(code_str)

    features = {}
    code_lower = code_str.lower()

    # --- 基礎文字特徵 ---
    features['code_length'] = len(code_str)
    features['line_count'] = code_str.count('\n') + 1
    features['avg_line_length'] = features['code_length'] / features['line_count']

    # --- 熵值 (Shannon Entropy) ---
    if len(code_str) > 0:
        freq = Counter(code_str)
        probs = [c / len(code_str) for c in freq.values()]
        features['entropy'] = -sum(p * np.log2(p) for p in probs if p > 0)
    else:
        features['entropy'] = 0

    # --- AMSI 特定關鍵字 ---
    amsi_keywords = [
        'amsiutils', 'amsiinitfailed', 'amsicontext', 'amsisession',
        'amsiscanbuffer', 'amsiscanstring', 'amsiopensession', 'amsiclose',
        'amsiinitialize', 'amsi.dll', 'amsi_result', 'amsienable'
    ]
    features['amsi_keyword_count'] = sum(1 for kw in amsi_keywords if kw in code_lower)
    features['has_amsi_keyword'] = 1 if features['amsi_keyword_count'] > 0 else 0

    # --- Win32 API 呼叫 ---
    win32_apis = [
        'virtualprotect', 'getprocaddress', 'loadlibrary',
        'writeprocessmemory', 'readprocessmemory', 'virtualalloc',
        'ntsetcontextthread', 'setthreadcontext', 'getthreadcontext',
        'addvectoredexceptionhandler', 'rtlmovememory', 'copymemory'
    ]
    features['win32_api_count'] = sum(1 for api in win32_apis if api in code_lower)
    features['has_virtualprotect'] = 1 if 'virtualprotect' in code_lower else 0
    features['has_getprocaddress'] = 1 if 'getprocaddress' in code_lower else 0
    features['has_loadlibrary'] = 1 if 'loadlibrary' in code_lower else 0

    # --- .NET 反射 ---
    reflection_indicators = [
        'gettype', 'getfield', 'setvalue', 'getmethod', 'getmethods',
        'bindingflags', 'nonpublic', 'assembly.gettype',
        'runtimehelpers', 'preparemethod', 'methodhandle',
        'getfunctionpointer', 'methodimpl'
    ]
    features['reflection_count'] = sum(1 for r in reflection_indicators if r in code_lower)
    features['has_reflection'] = 1 if features['reflection_count'] > 0 else 0

    # --- Marshal 操作 ---
    marshal_ops = [
        'marshal::copy', 'marshal.copy', 'writebyte', 'writeint32',
        'writeintptr', 'readintptr', 'readbyte', 'allochglobal',
        'alloccolocal', 'structuretoptr'
    ]
    features['marshal_op_count'] = sum(1 for m in marshal_ops if m in code_lower)

    # --- 混淆指標 ---
    features['backtick_count'] = code_str.count('`')
    features['has_format_operator'] = 1 if '-f' in code_str and '{' in code_str else 0
    features['char_cast_count'] = len(re.findall(r'\[char\]\d+', code_str, re.I))
    features['string_concat_count'] = code_str.count("'+'") + code_str.count('"+"')
    features['plus_operator_density'] = code_str.count('+') / max(len(code_str), 1)

    # --- Base64 指標 ---
    features['has_base64'] = 1 if any(x in code_lower for x in [
        'frombase64', 'tobase64', '-encodedcommand', '-enc ',
        'convert]::frombase64', 'convert]::tobase64'
    ]) else 0

    # --- 記憶體操作指標 ---
    features['has_memory_patch_pattern'] = 1 if (
        'virtualprotect' in code_lower and
        ('marshal' in code_lower or 'copy' in code_lower)
    ) else 0

    features['hex_byte_array'] = 1 if re.search(r'0x[0-9a-fA-F]{2}.*0x[0-9a-fA-F]{2}', code_str) else 0
    features['has_page_rwx'] = 1 if '0x40' in code_str else 0

    # --- DllImport ---
    features['dllimport_count'] = len(re.findall(r'DllImport', code_str, re.I))
    features['has_add_type'] = 1 if 'add-type' in code_lower else 0

    # --- 登錄檔操作 ---
    features['has_registry_amsi'] = 1 if any(x in code_lower for x in [
        'amsi\\providers', 'amsienable', 'remove-item.*hklm',
        'fdb00e52-a214-4aa1-8fba-4357bb0072ec'
    ]) else 0

    # --- 執行策略/降級 ---
    features['has_ps_downgrade'] = 1 if re.search(r'-ver(sion)?\s+2', code_lower) else 0

    # --- ScriptBlock AST ---
    features['has_scriptblock_ast'] = 1 if any(x in code_lower for x in [
        'scriptblockast', 'endblock', 'getscriptblock', 'spoofedast'
    ]) else 0

    # --- Hardware Breakpoint ---
    features['has_hw_breakpoint'] = 1 if any(x in code_lower for x in [
        'setthreadcontext', 'dr0', 'dr7', 'context64',
        'addvectoredexceptionhandler', 'exception_single_step'
    ]) else 0

    # --- ETW 相關 ---
    features['has_etw_tamper'] = 1 if any(x in code_lower for x in [
        'etweventwrite', 'etweventsend'
    ]) else 0

    # --- 下載 cradle ---
    features['has_download_cradle'] = 1 if any(x in code_lower for x in [
        'downloadstring', 'downloadfile', 'invoke-webrequest',
        'wget ', 'curl ', 'iwr ', 'iex(', 'iex ('
    ]) else 0

    # --- CLR 層級操作 ---
    features['has_clr_targeting'] = 1 if any(x in code_lower for x in [
        'clr.dll', 'system.management.automation.dll',
        'scancontent', 'system_management_automation_ni'
    ]) else 0

    # --- 可疑比率 ---
    special_chars = sum(1 for c in code_str if not c.isalnum() and c != ' ')
    features['special_char_ratio'] = special_chars / max(len(code_str), 1)

    upper_count = sum(1 for c in code_str if c.isupper())
    lower_count = sum(1 for c in code_str if c.islower())
    features['case_ratio'] = upper_count / max(lower_count, 1)

    # --- 綜合風險分數 ---
    features['composite_risk'] = (
        features['amsi_keyword_count'] * 3 +
        features['win32_api_count'] * 2 +
        features['reflection_count'] * 2 +
        features['marshal_op_count'] * 2 +
        features['has_memory_patch_pattern'] * 5 +
        features['hex_byte_array'] * 3 +
        features['has_hw_breakpoint'] * 5 +
        features['has_scriptblock_ast'] * 5 +
        features['has_etw_tamper'] * 4 +
        features['dllimport_count'] * 2 +
        features['has_ps_downgrade'] * 2 +
        features['has_registry_amsi'] * 3 +
        features['has_clr_targeting'] * 4
    )

    return features


# 讀取惡意 Payload
df_payloads = pd.read_excel(DATASET_PATH, sheet_name='Payload_Samples')
df_signatures = pd.read_excel(DATASET_PATH, sheet_name='Detection_Signatures')

# 萃取特徵
print("  萃取惡意 Payload 特徵...")
malicious_features = [extract_features(code) for code in df_payloads['Payload_Code']]
df_mal = pd.DataFrame(malicious_features)
df_mal['label'] = 1  # 1 = malicious (AMSI bypass)
df_mal['label_name'] = 'AMSI_Bypass'
df_mal['source_id'] = df_payloads['Sample_ID'].values
df_mal['technique_name'] = df_payloads['Technique_Name'].values

print("  萃取正常指令特徵...")
benign_features = [extract_features(cmd) for cmd in benign_commands]
df_ben = pd.DataFrame(benign_features)
df_ben['label'] = 0  # 0 = benign
df_ben['label_name'] = 'Benign'
df_ben['source_id'] = [f'BEN-{i:03d}' for i in range(len(benign_commands))]
df_ben['technique_name'] = 'Normal_Command'

# 合併
df_all = pd.concat([df_mal, df_ben], ignore_index=True)
print(f"\n  總資料集: {len(df_all)} 筆 (Malicious: {df_mal.shape[0]}, Benign: {df_ben.shape[0]})")

# =============================================================================
# SECTION 3: 探索式資料分析 (EDA)
# =============================================================================
print("\n" + "=" * 70)
print("SECTION 3: 探索式資料分析 (EDA)")
print("=" * 70)

feature_cols = [c for c in df_all.columns if c not in ['label', 'label_name', 'source_id', 'technique_name']]
print(f"  特徵數量: {len(feature_cols)}")

# 特徵統計
print("\n  --- 特徵分佈比較 (Mean) ---")
comparison = pd.DataFrame({
    'Benign_Mean': df_all[df_all['label'] == 0][feature_cols].mean(),
    'Malicious_Mean': df_all[df_all['label'] == 1][feature_cols].mean(),
})
comparison['Diff_Ratio'] = (comparison['Malicious_Mean'] - comparison['Benign_Mean']) / (comparison['Benign_Mean'] + 1e-6)
comparison = comparison.sort_values('Diff_Ratio', ascending=False)
print(comparison.head(15).to_string())

# --- 圖 1: 特徵重要性差異 Top 15 ---
fig, axes = plt.subplots(2, 2, figsize=(18, 14))
fig.suptitle('AMSI Bypass Detection — Exploratory Data Analysis', fontsize=16, fontweight='bold')

top_features = comparison.head(15)
ax1 = axes[0, 0]
x = range(len(top_features))
ax1.barh(range(len(top_features)), top_features['Malicious_Mean'], alpha=0.7, label='Malicious', color='#e74c3c')
ax1.barh(range(len(top_features)), top_features['Benign_Mean'], alpha=0.7, label='Benign', color='#2ecc71')
ax1.set_yticks(range(len(top_features)))
ax1.set_yticklabels(top_features.index, fontsize=8)
ax1.set_xlabel('Mean Value')
ax1.set_title('Top 15 Discriminative Features (Mean Comparison)')
ax1.legend()
ax1.invert_yaxis()

# --- 圖 2: Composite Risk Score 分佈 ---
ax2 = axes[0, 1]
ax2.hist(df_all[df_all['label'] == 0]['composite_risk'], bins=20, alpha=0.7, label='Benign', color='#2ecc71', edgecolor='black')
ax2.hist(df_all[df_all['label'] == 1]['composite_risk'], bins=20, alpha=0.7, label='Malicious', color='#e74c3c', edgecolor='black')
ax2.set_xlabel('Composite Risk Score')
ax2.set_ylabel('Count')
ax2.set_title('Composite Risk Score Distribution')
ax2.legend()
ax2.axvline(x=5, color='orange', linestyle='--', alpha=0.8, label='Threshold=5')

# --- 圖 3: Entropy 分佈 ---
ax3 = axes[1, 0]
ax3.hist(df_all[df_all['label'] == 0]['entropy'], bins=20, alpha=0.7, label='Benign', color='#2ecc71', edgecolor='black')
ax3.hist(df_all[df_all['label'] == 1]['entropy'], bins=20, alpha=0.7, label='Malicious', color='#e74c3c', edgecolor='black')
ax3.set_xlabel('Shannon Entropy')
ax3.set_ylabel('Count')
ax3.set_title('Shannon Entropy Distribution')
ax3.legend()

# --- 圖 4: 關鍵二元特徵比較 ---
ax4 = axes[1, 1]
binary_features = ['has_amsi_keyword', 'has_virtualprotect', 'has_reflection',
                   'has_memory_patch_pattern', 'hex_byte_array', 'has_add_type',
                   'has_hw_breakpoint', 'has_scriptblock_ast', 'has_etw_tamper']
mal_rates = [df_all[df_all['label'] == 1][f].mean() for f in binary_features]
ben_rates = [df_all[df_all['label'] == 0][f].mean() for f in binary_features]
x_pos = np.arange(len(binary_features))
ax4.bar(x_pos - 0.2, mal_rates, 0.4, label='Malicious', color='#e74c3c', alpha=0.8)
ax4.bar(x_pos + 0.2, ben_rates, 0.4, label='Benign', color='#2ecc71', alpha=0.8)
ax4.set_xticks(x_pos)
ax4.set_xticklabels([f.replace('has_', '').replace('_', '\n') for f in binary_features], fontsize=7, rotation=45, ha='right')
ax4.set_ylabel('Proportion (0-1)')
ax4.set_title('Binary Feature Prevalence by Class')
ax4.legend()

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'amsi_eda_analysis.png'), dpi=150, bbox_inches='tight')
plt.close()
print("  [OK] EDA 圖表已儲存: amsi_eda_analysis.png")

# =============================================================================
# SECTION 4: 模型訓練與評估
# =============================================================================
print("\n" + "=" * 70)
print("SECTION 4: 模型訓練與評估")
print("=" * 70)

X = df_all[feature_cols].values
y = df_all['label'].values

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced'),
    'XGBoost': XGBClassifier(n_estimators=100, max_depth=6, random_state=42, scale_pos_weight=len(y[y==0])/max(len(y[y==1]),1), eval_metric='logloss', verbosity=0),
    'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced'),
    'SVM (RBF)': SVC(kernel='rbf', probability=True, random_state=42, class_weight='balanced'),
    'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42),
}

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

results = {}
print("\n  --- 5-Fold Stratified Cross-Validation ---")
print(f"  {'Model':<25} {'Accuracy':>10} {'F1-Score':>10} {'Precision':>10} {'Recall':>10}")
print("  " + "-" * 65)

for name, model in models.items():
    X_input = X_scaled if name in ['Logistic Regression', 'SVM (RBF)'] else X

    acc_scores = cross_val_score(model, X_input, y, cv=cv, scoring='accuracy')
    f1_scores = cross_val_score(model, X_input, y, cv=cv, scoring='f1')
    prec_scores = cross_val_score(model, X_input, y, cv=cv, scoring='precision')
    rec_scores = cross_val_score(model, X_input, y, cv=cv, scoring='recall')

    results[name] = {
        'accuracy': acc_scores.mean(),
        'f1': f1_scores.mean(),
        'precision': prec_scores.mean(),
        'recall': rec_scores.mean(),
        'acc_std': acc_scores.std(),
        'f1_std': f1_scores.std(),
    }
    print(f"  {name:<25} {acc_scores.mean():>9.4f} {f1_scores.mean():>9.4f} {prec_scores.mean():>9.4f} {rec_scores.mean():>9.4f}")

# 訓練最佳模型 (全資料集用於特徵重要性分析)
best_model_name = max(results, key=lambda k: results[k]['f1'])
print(f"\n  最佳模型 (by F1): {best_model_name} (F1={results[best_model_name]['f1']:.4f})")

rf_full = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, class_weight='balanced')
rf_full.fit(X, y)

xgb_full = XGBClassifier(n_estimators=200, max_depth=6, random_state=42, eval_metric='logloss', verbosity=0)
xgb_full.fit(X, y)

# --- 圖 5: 模型效能比較 + 特徵重要性 ---
fig, axes = plt.subplots(2, 2, figsize=(18, 14))
fig.suptitle('AMSI Bypass Detection — Model Performance & Feature Importance', fontsize=16, fontweight='bold')

# 模型比較
ax1 = axes[0, 0]
model_names = list(results.keys())
metrics_data = {
    'Accuracy': [results[m]['accuracy'] for m in model_names],
    'F1-Score': [results[m]['f1'] for m in model_names],
    'Precision': [results[m]['precision'] for m in model_names],
    'Recall': [results[m]['recall'] for m in model_names],
}
x_pos = np.arange(len(model_names))
width = 0.2
for i, (metric, values) in enumerate(metrics_data.items()):
    ax1.bar(x_pos + i * width, values, width, label=metric, alpha=0.85)
ax1.set_xticks(x_pos + width * 1.5)
ax1.set_xticklabels(model_names, rotation=20, ha='right', fontsize=8)
ax1.set_ylabel('Score')
ax1.set_title('5-Fold CV Performance Comparison')
ax1.legend(fontsize=8)
ax1.set_ylim(0, 1.15)
for i, (metric, values) in enumerate(metrics_data.items()):
    for j, v in enumerate(values):
        ax1.text(j + i * width, v + 0.02, f'{v:.2f}', ha='center', fontsize=6)

# Random Forest 特徵重要性
ax2 = axes[0, 1]
rf_importances = rf_full.feature_importances_
sorted_idx = np.argsort(rf_importances)[-15:]
ax2.barh(range(len(sorted_idx)), rf_importances[sorted_idx], color='#3498db', alpha=0.8)
ax2.set_yticks(range(len(sorted_idx)))
ax2.set_yticklabels([feature_cols[i] for i in sorted_idx], fontsize=8)
ax2.set_xlabel('Importance')
ax2.set_title('Random Forest — Top 15 Feature Importance')

# XGBoost 特徵重要性
ax3 = axes[1, 0]
xgb_importances = xgb_full.feature_importances_
sorted_idx_xgb = np.argsort(xgb_importances)[-15:]
ax3.barh(range(len(sorted_idx_xgb)), xgb_importances[sorted_idx_xgb], color='#e67e22', alpha=0.8)
ax3.set_yticks(range(len(sorted_idx_xgb)))
ax3.set_yticklabels([feature_cols[i] for i in sorted_idx_xgb], fontsize=8)
ax3.set_xlabel('Importance')
ax3.set_title('XGBoost — Top 15 Feature Importance')

# Confusion Matrix (RF on full data as reference)
ax4 = axes[1, 1]
y_pred_rf = rf_full.predict(X)
cm = confusion_matrix(y, y_pred_rf)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax4,
            xticklabels=['Benign', 'AMSI Bypass'], yticklabels=['Benign', 'AMSI Bypass'])
ax4.set_xlabel('Predicted')
ax4.set_ylabel('Actual')
ax4.set_title('Confusion Matrix (Random Forest — Full Training Data)')

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'amsi_model_performance.png'), dpi=150, bbox_inches='tight')
plt.close()
print("  [OK] 模型效能圖表已儲存: amsi_model_performance.png")

# =============================================================================
# SECTION 5: ROC Curve 與 Precision-Recall Curve
# =============================================================================
print("\n" + "=" * 70)
print("SECTION 5: ROC & Precision-Recall Curves")
print("=" * 70)

fig, axes = plt.subplots(1, 2, figsize=(16, 6))
fig.suptitle('AMSI Bypass Detection — ROC & Precision-Recall Curves (5-Fold CV)', fontsize=14, fontweight='bold')

colors = ['#e74c3c', '#3498db', '#2ecc71', '#9b59b6', '#e67e22']

for idx, (name, model) in enumerate(models.items()):
    X_input = X_scaled if name in ['Logistic Regression', 'SVM (RBF)'] else X

    mean_fpr = np.linspace(0, 1, 100)
    tprs = []
    aucs = []
    precisions_interp = []
    pr_aucs = []

    for train_idx, test_idx in cv.split(X_input, y):
        X_train, X_test = X_input[train_idx], X_input[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        model_clone = model.__class__(**model.get_params())
        model_clone.fit(X_train, y_train)
        y_proba = model_clone.predict_proba(X_test)[:, 1]

        fpr, tpr, _ = roc_curve(y_test, y_proba)
        roc_auc = auc(fpr, tpr)
        aucs.append(roc_auc)
        tprs.append(np.interp(mean_fpr, fpr, tpr))

        precision, recall, _ = precision_recall_curve(y_test, y_proba)
        pr_aucs.append(auc(recall, precision))

    mean_tpr = np.mean(tprs, axis=0)
    mean_auc = np.mean(aucs)

    axes[0].plot(mean_fpr, mean_tpr, color=colors[idx], lw=2,
                 label=f'{name} (AUC={mean_auc:.3f})')

axes[0].plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5)
axes[0].set_xlabel('False Positive Rate')
axes[0].set_ylabel('True Positive Rate')
axes[0].set_title('ROC Curves')
axes[0].legend(fontsize=8)
axes[0].grid(True, alpha=0.3)

# PR Curve (simplified: full data)
for idx, (name, model) in enumerate(models.items()):
    X_input = X_scaled if name in ['Logistic Regression', 'SVM (RBF)'] else X
    model_clone = model.__class__(**model.get_params())
    model_clone.fit(X_input, y)
    y_proba = model_clone.predict_proba(X_input)[:, 1]
    precision, recall, _ = precision_recall_curve(y, y_proba)
    pr_auc = auc(recall, precision)
    axes[1].plot(recall, precision, color=colors[idx], lw=2,
                 label=f'{name} (AUC={pr_auc:.3f})')

axes[1].set_xlabel('Recall')
axes[1].set_ylabel('Precision')
axes[1].set_title('Precision-Recall Curves')
axes[1].legend(fontsize=8)
axes[1].grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'amsi_roc_pr_curves.png'), dpi=150, bbox_inches='tight')
plt.close()
print("  [OK] ROC & PR 曲線已儲存: amsi_roc_pr_curves.png")

# =============================================================================
# SECTION 6: Detection Signatures 覆蓋率分析
# =============================================================================
print("\n" + "=" * 70)
print("SECTION 6: Detection Signatures 覆蓋率分析")
print("=" * 70)

# 測試每條 Regex 對所有 Payload 的覆蓋率
print("\n  --- Regex 偵測規則 vs Payload 覆蓋矩陣 ---")

coverage_matrix = []
all_codes = list(df_payloads['Payload_Code'].values) + benign_commands
all_labels = ['MAL'] * len(df_payloads) + ['BEN'] * len(benign_commands)
all_ids = list(df_payloads['Sample_ID'].values) + [f'BEN-{i:03d}' for i in range(len(benign_commands))]

for _, sig in df_signatures.iterrows():
    regex_str = str(sig['Regex_or_Rule'])
    if regex_str.startswith('hex:'):
        continue  # Skip YARA hex rules

    row = {'Signature_ID': sig['Signature_ID'], 'Pattern': sig['Pattern_Description'][:50]}
    tp, fp, fn, tn = 0, 0, 0, 0

    for code, label in zip(all_codes, all_labels):
        try:
            match = bool(re.search(regex_str, str(code), re.IGNORECASE | re.DOTALL))
        except re.error:
            match = False

        if label == 'MAL':
            if match:
                tp += 1
            else:
                fn += 1
        else:
            if match:
                fp += 1
            else:
                tn += 1

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-6)
    fpr_rate = fp / max(fp + tn, 1)

    row.update({
        'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn,
        'Precision': round(precision, 3),
        'Recall': round(recall, 3),
        'F1': round(f1, 3),
        'FPR': round(fpr_rate, 4)
    })
    coverage_matrix.append(row)

df_coverage = pd.DataFrame(coverage_matrix)
print(df_coverage.to_string(index=False))

# 綜合覆蓋率
total_mal = len(df_payloads)
detected_by_any = set()
for _, sig in df_signatures.iterrows():
    regex_str = str(sig['Regex_or_Rule'])
    if regex_str.startswith('hex:'):
        continue
    for i, code in enumerate(df_payloads['Payload_Code'].values):
        try:
            if re.search(regex_str, str(code), re.IGNORECASE | re.DOTALL):
                detected_by_any.add(i)
        except re.error:
            pass

print(f"\n  綜合覆蓋率: {len(detected_by_any)}/{total_mal} ({100*len(detected_by_any)/total_mal:.1f}%) 的惡意 Payload 至少被一條規則偵測")
undetected = set(range(total_mal)) - detected_by_any
if undetected:
    print("  未被偵測的 Payload:")
    for idx in undetected:
        print(f"    - {df_payloads.iloc[idx]['Sample_ID']}: {df_payloads.iloc[idx]['Technique_Name']}")

# --- 圖 6: 覆蓋率分析 ---
fig, axes = plt.subplots(1, 2, figsize=(16, 6))
fig.suptitle('Detection Signature Coverage Analysis', fontsize=14, fontweight='bold')

ax1 = axes[0]
if len(df_coverage) > 0:
    sig_ids = df_coverage['Signature_ID']
    ax1.barh(range(len(sig_ids)), df_coverage['Recall'], alpha=0.7, color='#3498db', label='Recall')
    ax1.barh(range(len(sig_ids)), df_coverage['Precision'], alpha=0.5, color='#e74c3c', label='Precision')
    ax1.set_yticks(range(len(sig_ids)))
    ax1.set_yticklabels(sig_ids, fontsize=7)
    ax1.set_xlabel('Score')
    ax1.set_title('Per-Signature Precision & Recall')
    ax1.legend()
    ax1.invert_yaxis()

# Per-payload detection count
ax2 = axes[1]
payload_detect_counts = []
for i, code in enumerate(df_payloads['Payload_Code'].values):
    count = 0
    for _, sig in df_signatures.iterrows():
        regex_str = str(sig['Regex_or_Rule'])
        if regex_str.startswith('hex:'):
            continue
        try:
            if re.search(regex_str, str(code), re.IGNORECASE | re.DOTALL):
                count += 1
        except re.error:
            pass
    payload_detect_counts.append(count)

colors_bar = ['#e74c3c' if c == 0 else '#e67e22' if c <= 2 else '#2ecc71' for c in payload_detect_counts]
ax2.barh(range(len(payload_detect_counts)), payload_detect_counts, color=colors_bar, alpha=0.8)
ax2.set_yticks(range(len(payload_detect_counts)))
ax2.set_yticklabels(df_payloads['Sample_ID'], fontsize=7)
ax2.set_xlabel('Number of Matching Signatures')
ax2.set_title('Per-Payload Detection Coverage')
ax2.invert_yaxis()

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'amsi_coverage_analysis.png'), dpi=150, bbox_inches='tight')
plt.close()
print("  [OK] 覆蓋率分析圖表已儲存: amsi_coverage_analysis.png")

# =============================================================================
# SECTION 7: Payload 文字層級 TF-IDF 分析
# =============================================================================
print("\n" + "=" * 70)
print("SECTION 7: TF-IDF Token 分析")
print("=" * 70)

all_texts = list(df_payloads['Payload_Code'].astype(str)) + benign_commands
all_y = [1] * len(df_payloads) + [0] * len(benign_commands)

tfidf = TfidfVectorizer(
    max_features=200,
    token_pattern=r'(?u)\b[A-Za-z_][A-Za-z0-9_\.]{2,}\b',
    ngram_range=(1, 2),
    sublinear_tf=True
)
X_tfidf = tfidf.fit_transform(all_texts)

feature_names = tfidf.get_feature_names_out()
mal_mean = X_tfidf[:len(df_payloads)].toarray().mean(axis=0)
ben_mean = X_tfidf[len(df_payloads):].toarray().mean(axis=0)
diff = mal_mean - ben_mean

top_mal_tokens = np.argsort(diff)[-20:][::-1]
top_ben_tokens = np.argsort(diff)[:10]

print("\n  Top 20 AMSI Bypass 特有 Token (TF-IDF):")
for idx in top_mal_tokens:
    print(f"    {feature_names[idx]:<35} diff={diff[idx]:.4f}")

print("\n  Top 10 Benign 特有 Token (TF-IDF):")
for idx in top_ben_tokens:
    print(f"    {feature_names[idx]:<35} diff={diff[idx]:.4f}")

# TF-IDF + RandomForest
from sklearn.model_selection import cross_val_predict
rf_tfidf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced')
tfidf_f1 = cross_val_score(rf_tfidf, X_tfidf.toarray(), np.array(all_y), cv=cv, scoring='f1')
print(f"\n  TF-IDF + Random Forest F1: {tfidf_f1.mean():.4f} (+/- {tfidf_f1.std():.4f})")

# =============================================================================
# SECTION 8: 輸出綜合報告
# =============================================================================
print("\n" + "=" * 70)
print("SECTION 8: 綜合報告輸出")
print("=" * 70)

# 儲存特徵資料集供後續使用
df_all.to_csv(os.path.join(OUTPUT_DIR, 'amsi_features_dataset.csv'), index=False)
print("  [OK] 特徵資料集已儲存: amsi_features_dataset.csv")

# 儲存覆蓋率矩陣
df_coverage.to_csv(os.path.join(OUTPUT_DIR, 'amsi_signature_coverage.csv'), index=False)
print("  [OK] 覆蓋率矩陣已儲存: amsi_signature_coverage.csv")

# 產出 Classification Report (RF full data)
print("\n  --- Random Forest Classification Report (Full Data) ---")
y_pred_final = rf_full.predict(X)
print(classification_report(y, y_pred_final, target_names=['Benign', 'AMSI_Bypass']))

# =============================================================================
# SECTION 9: 產出分析摘要報告 (Markdown)
# =============================================================================
report = f"""# AMSI Bypass Detection — ML 分析報告

## 1. 資料集概述
| 項目 | 數量 |
|------|------|
| 惡意 Payload (AMSI Bypass) | {len(df_payloads)} |
| 正常指令 (Benign) | {len(benign_commands)} |
| 總樣本數 | {len(df_all)} |
| 萃取特徵數 | {len(feature_cols)} |
| 偵測規則數 | {len(df_signatures)} |

## 2. 模型效能比較 (5-Fold Stratified CV)
| Model | Accuracy | F1-Score | Precision | Recall |
|-------|----------|----------|-----------|--------|
"""

for name, r in results.items():
    report += f"| {name} | {r['accuracy']:.4f} | {r['f1']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} |\n"

report += f"""
**最佳模型**: {best_model_name} (F1={results[best_model_name]['f1']:.4f})

## 3. 最重要的偵測特徵 (Random Forest Top 10)
| Rank | Feature | Importance |
|------|---------|------------|
"""

rf_imp_sorted = np.argsort(rf_full.feature_importances_)[::-1][:10]
for rank, idx in enumerate(rf_imp_sorted, 1):
    report += f"| {rank} | {feature_cols[idx]} | {rf_full.feature_importances_[idx]:.4f} |\n"

report += f"""
## 4. 偵測規則覆蓋率
- 綜合覆蓋率: **{len(detected_by_any)}/{total_mal} ({100*len(detected_by_any)/total_mal:.1f}%)**
"""

if undetected:
    report += "\n### 偵測缺口 (未被任何 Regex 規則覆蓋的 Payload)\n"
    for idx in undetected:
        report += f"- **{df_payloads.iloc[idx]['Sample_ID']}**: {df_payloads.iloc[idx]['Technique_Name']}\n"

report += f"""
## 5. TF-IDF 文字分析
- TF-IDF + Random Forest F1: **{tfidf_f1.mean():.4f}**
- 最具區別力的 AMSI Bypass Token: {', '.join(feature_names[i] for i in top_mal_tokens[:10])}

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
"""

with open(os.path.join(OUTPUT_DIR, 'amsi_ml_analysis_report.md'), 'w', encoding='utf-8') as f:
    f.write(report)
print("  [OK] 分析報告已儲存: amsi_ml_analysis_report.md")

print("\n" + "=" * 70)
print("ALL DONE — 所有分析完成")
print("=" * 70)
