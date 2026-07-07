# File Integrity & Anti-Ransomware Monitor (FIM)

A real-time Desktop Security application built using **Python 3** that monitors directory changes, safeguards data using cryptographic verification ($SHA-256$), and employs behavioral analysis rules to instantly flag and isolate potential Ransomware attacks.

Developed as a **BCA 5th Semester Mini-Project**.

---

## 🚀 Key Features

* **Real-time Event Hooking:** Direct OS kernel-level monitoring using the `watchdog` API for near-zero latency tracking of creations, modifications, deletions, and renames.
* **Cryptographic Integrity Check:** Generates a state snapshot by assigning unique $SHA-256$ cryptographic signatures to target files, verifying raw content alterations regardless of file metadata manipulation.
* **Dual-Indicator Ransomware Mitigation:**
  * **Signature Analysis:** Real-time extension blacklist interception against threat delivery payloads (`.locked`, `.crypto`, `.enc`, etc.).
  * **Behavioral Analysis:** Implements a sliding-window data queue structure to capture mass file alteration anomalies (e.g., more than 5 edits within a rolling 2-second buffer).
* **Automated Incident Response Isolation:** Decoupled architecture that instantly flags `is_isolated` status on breach identification, locking down the file monitoring thread to minimize target system resource consumption while a threat is active.
* **User-Friendly Desktop Console:** Clean UI designed with themed Tkinter components (`ttk`) featuring chronological data grid logging.

---

## 🛠️ Project Architecture

```text
FIM_Project/
│
├── main.py            # Desktop GUI application driver (Tkinter Layout Engine)
├── fim_backend.py     # Core Hashing Algorithms & File-System Watchdog Callbacks
└── README.md          # Project documentation report


Installation & Workspace Setup
------------------------------

Prerequisites
*************
   Download Python 3.8+ via python.org/downloads. Ensure you check the box for "Add python.exe to PATH" during setup.
   Ensure you have an appropriate text editor or IDE (e.g., Visual Studio Code).
Step-by-Step Execution
Clone or create the project folder:
Create a root directory named FIM_Project and place main.py and fim_backend.py inside.

Open Terminal / Command Prompt inside the project directory:
---------------------------------------------------------

    cd path/to/FIM_Project

Install the third-party OS monitoring dependency:
-------------------------------------------------------
    pip install watchdog

Launch the application interface:
-------------------------------------------------------
python main.py   


Evaluation & Demo Testing Scenarios
*******************************************************
Use a dedicated, non-critical test folder (e.g., an empty directory on your desktop named SandboxTest) to safely evaluate the security rules during your practical demo:
**************************************************************************************************************************************
1. Verification of Normal File Integrity
Action: Select your test folder, click Start Real-Time Guard, then create and save edits inside a normal text file (e.g., test.txt).

Result: The system tracks the event cleanly, printing CREATED logs and capturing MODIFIED - Hash Mismatch as soon as internal text structures shift.
************************************************************************************************************************************
2. Known Ransomware Signature Detection
----------------------------------------
Action: Right-click an asset inside your watched directory and change its name extension to document.locked.

Result: The backend captures the file structure change instantly, halts processing, and displays a critical warning alert window before the encryption process can spread further.
*************************************************************************************************************************************

3. High-Frequency Modification Anomaly Detection
-------------------------------------------------
Action: Rapidly copy/paste multiple files into the directory or run a script that repeatedly writes edits 6 or more times within 2 seconds.

Result: The Sliding Window Rate-Limiter trips. The system visually locks out modifications to protect CPU usage and blocks further input until it is manually re-armed.
****************************************************************************************************************************************