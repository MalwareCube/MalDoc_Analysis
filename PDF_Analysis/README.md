# Performing Static PDF Analysis

## Scenario
Your SOC team received a ticket for a suspicious email reported by an employee. The email contains an attachment—a PDF document—that appears to be part of a phishing attempt. Your goal is to analyze the email to determine if the attached PDF is malicious and to identify any Indicators of Compromise (IoCs). 

In this scenario, you will explore analysis techniques for safely identifying and analyzing malicious PDFs. You'll learn the composition and structure of PDFs, along with some simple tools that can be used to perform static analysis to detect malware artifacts and uncover embedded payloads or scripts.

The email can be found in this directory, named `Tax_Report.eml`. A preview of the email in the Mozilla Thunderbird email client can be seen here:

![Email excerpt](https://github.com/user-attachments/assets/df10d0c1-67ae-443b-8d05-2d1bde7fc048)

As we can see above, the email references a PDF for review which has been attached to the email as `Tax_Report.pdf`.

## Portable Document Format (PDF)

![PDF Icon](https://github.com/user-attachments/assets/393a0a25-e9f1-4e72-bc83-89302a947dc1)

A PDF, or Portable Document Format, is a file format created by Adobe in the early 1990s to present documents consistently across different devices and operating systems. Because of this consistency, PDFs are commonly used for sharing documents that need to retain their formatting.

However, its ubiquity in the workplace means that, along with malicious Office documents (MalDocs), malicious PDFs are among the most prevalent attachment-based threats organizations encounter. Organizations and individuals often trust PDFs because they are a standard format for invoices, contracts, reports, and other official documents. This trust, along with the widespread use of PDF readers and their compatibility across devices, makes them a natural choice for attackers looking to bypass security measures and evade basic email attachment filters.

In most cases, attackers don't even go as far as to embed malicious content inside of PDF files themselves. Arguably, the most common technique involves simply containing a clickable URL or link within a PDF that then leads to a malicious webpage or drive-by download.

## Email Attachments

Email attachments are files sent alongside the email, which can range from documents (Office documents, PDFs, etc.) to images (JPGs, PNGs, etc.) or compressed archives (`.zip` files, etc.). These files are typically encoded within the email as a **base64** encoded string, depending on the encoding method used, to ensure safe transport across different email clients and systems.

If we were to open up the `Tax_Report.eml` file in a text editor, we'll find that the attachment has been embedded at the bottom of the email file. 

In this lab, we'll learn how to extract and analyze these attachments to assess them for potential malware. Through various email headers, such as the `Content-Type`, the `Content-Transfer-Encoding`, and the `Content-Disposition`, we can infer that the email attachment is titled `Tax_Report.pdf` and has been encoded using `base64`. 

These are the same headers that an email client would check in order to display a preview of the file in the client or browser.

![The attachment section of an EML file](https://github.com/user-attachments/assets/bde6ef8f-f46f-4968-807a-765b496acbca)

There are several ways to extract attachments from an email for analysis, such as saving it locally from an email client, downloading it from a ticketing system in the case of a phishing investigation, or using scripts to directly dump the attachment. Each approach has its pros and cons.

In some cases, it's best—or not even necessary—to write the attachment to disk to perform a basic reputation analysis.

### eioc.py
This leads us into tools like `eioc.py`, which is a [Python script](https://github.com/MalwareCube/Email-IOC-Extractor) designed to aid in email forensic analysis by extracting various components from email files such as IP addresses, URLs, headers, and attachment metadata.

If we run `eioc.py` against an email, it will provide us with several pieces of parsed and extracted indicators like IP addresses and important email headers, including the filenames and cryptographic hash values of any attachments.

To perform this, we can simply use Python to call the `eioc.py` script, which is located in the `Tools` directory, and provide it the `Tax_Report.eml` file:

```
python3 Tools/eioc.py Tax_Report.eml
```

![The output of eioc.py](https://github.com/user-attachments/assets/b9b06d2d-f625-4578-a23e-bb753a48e58a)

And with a single command, we've extracted the MD5, SHA1, and SHA256 hash values of the PDF without even writing it to disk, minimizing the risk of accidental clicks or execution.

We can now take any of these hash values and perform a reputation lookup by checking its hash against threat intelligence databases to determine if the file is known to be malicious.

For example, if we head over to [VirusTotal](https://virustotal.com), we can search for the file's MD5 hash `9080bf37c122cdd9d4eb9e87e95ba614`: 

![Virustotal submission page](https://github.com/user-attachments/assets/abb3a5cd-d729-4905-ab30-0f1e7b821a92)

Upon doing so, we will quickly discover that this file was flagged as malicious by almost 30 security vendors, all claiming that the file is some kind of **trojan** used in phishing attacks.

![Virustotal results page](https://github.com/user-attachments/assets/15a22c7a-42d6-4ae4-9ed9-3339dc2f9a58)

## Extracting Email Attachments
In some cases, we may still need to extract the attachment from an email in order to perform static and dynamic malware analysis. With an attachment safely extracted, an analyst can perform static analysis to inspect the file's structure, metadata, and embedded objects, as well as dynamic analysis by safely executing the file in a controlled environment to observe its behavior.

### emldump.py
One useful tool for extracting email attachments is `emldump.py`, developed by [Didier Stevens](https://github.com/DidierStevens/DidierStevensSuite/tree/master). This script is designed to parse email files and extract the attachments without having to open them in an email client. It also can allow us to automate the process of attachment extraction, making it easier to handle larger volumes of suspicious emails at once.

To safely extract the PDF from the email, we can simply run `emldump.py` and point it to the email in question:

```
python3 Tools/emldump.py Tax_Report.eml
```

This command extracts the content of the `.eml` file and displays its multipart structure in the form of various streams or indexes. Interestingly, the fourth stream (`4:`) is labeled `Tax_Report.pdf`. The `application/pdf` MIME type indicates a PDF file, and its size is 49,272 bytes.

![emldump.py output](https://github.com/user-attachments/assets/76a9b307-2e70-4846-be09-337a15988875)

Now that we know the correct stream we want to extract, we can run the command again to select it using the `-s 4` argument (to indicate the fourth stream), along with `-d` to dump the file to disk. If we run this as is, the contents of the file will be dumped to the terminal. Instead, we want to direct the output to its own file using the `>` operator:

```
python3 Tools/emldump.py Tax_Report.eml -s 4 -d > Tax_Report.pdf
```
![emldump.py output](https://github.com/user-attachments/assets/dc5f4de1-f3bf-4d76-9a43-353d4ac39e69)

To further verify we've extracted the correct file, we can run `md5sum` against the file and compare it to our output from `eioc.py`:

```
md5sum Tax_Report.pdf
```

![md5sum output](https://github.com/user-attachments/assets/6c415030-7af2-47d5-a0f2-ef1963b3179d)

And we have a match!

Now that we've successfully extracted the suspicious attachment, let's turn to understanding the structure of PDF files and how we can analyze them for potential malware.

## PDF-Parser
As mentioned previously, embedding malicious URLs or links inside PDFs is one of the most common forms of PDF weaponization. While it is possible to open the PDF in a viewer or preview mode and hover over links or buttons to identify URLs, this approach is neither the most efficient nor the safest. It relies on manual inspection, which can be time-consuming for larger PDFs. Additionally, links may be hidden or obfuscated, and there is always the risk of accidentally clicking on them. 

For example, when opening the extracted `Tax_Report.pdf` file in a PDF viewer, we'll see a common form of PDF phishing, combining impersonation with a call-to-action URL. When hovering over the download button, we can identify the URL the attacker is attempting to get us to click:

![PDF Rendering](https://github.com/user-attachments/assets/b018cd55-95ef-4a59-ad41-36c648661350)

Fortunately, there are several tools out there that can assist us in safely extracting these URLs or indicators. Another useful Python-based tool developed by [Didier Stevens](https://github.com/DidierStevens/DidierStevensSuite/tree/master) is `pdf-parser.py`. PDF-Parser will parse a PDF document to identify the fundamental elements used in the analyzed file. It's widely used in malware analysis and digital forensics to inspect PDF documents for suspicious content, such as URLs, embedded JavaScript, obfuscated code, or hidden objects that might execute harmful actions when opened.

To begin, call the `pdf-parser.py` script from the `Tools/` directory, and point it to the `Tax_Report.pdf` file:

```
python3 Tools/pdf-parser.py Tax_Report.pdf
```

![pdf-parser.py output](https://github.com/user-attachments/assets/0e752930-a225-4aed-9ae2-05858fc36330)

As we run the command, we'll receive the entire parsed structure of the PDF file, broken into objects with metadata, links, resources, and document organization. Each structure is broken down into individual object (`obj`) streams, each containing a `Type`, such as `/Catalog` (which represents the root object of the PDF), `/Pages` (which organizes the document's pages), `/URI` (which points to an embedded URL), and many more.

Obviously, this is a lot of output to manually parse through. Fortunately, we can refine our search through this output using the `-s` argument. Since our focus is on enumerating and extracting URLs, we can use the `"/URI"` search operator to specifically retrieve URL-related structures.

```
python3 Tools/pdf-parser.py Tax_Report.pdf -s "/URI"
```

![pdf-parser.py output](https://github.com/user-attachments/assets/e5fa9f5a-41ac-49d2-b9f1-6a53b5da5848)

And just like that, we've managed to extract the URL from the PDF!

```
https://monitor.clickcease.com//tracker/tracker?id=te2024nKEUFIqUrNt12&adpos=&nw=a&url=https://ecy.wcs520.com/wp-content/themes/evita/red.php?utm_content=VnsDcPoijH&session_id=kXwPx3abVGJRsx2KDH8f&id=YKasm&filter=RwauvDwqWe-HLWCJ&lang=de&locale=FR
```

As a logical next step in our investigation, we could now perform URL and domain reputation checks along with further analysis on the URL we've identified.

### Example 2

To demonstrate how quick this process can be, let's run the same command once more. This time, point to the `Statement.pdf` file located in the same directory:

```
python3 Tools/pdf-parser.py Statement.pdf -s "/URI"
```

![pdf-parser.py output](https://github.com/user-attachments/assets/d47249f4-0375-4967-9084-c340765c91a9)

And with that, we've quickly identified the URL embedded in this PDF.

```
https://script.google.com/macros/s/AKfycbwABk1V3TSZ7dwG4lOsmbewJuEt2TExXS8cSaYuhcQwcxoffsDSJS8VLFR4h0pkJFwkUQ/exec
```

## PDFiD
In addition to embedding URLs inside of PDFs, an attacker might also attempt to embed malicious scripts or even entire documents for PDF viewing applications that will automatically execute when a PDF is opened.

Along with `pdf-parser.py`, the [Didier Stevens](https://github.com/DidierStevens/DidierStevensSuite/tree/master) suite of tools includes `pdfid.py`. This tool is not a PDF parser on its own, but it will scan a file to look for certain PDF keywords, allowing you to identify PDF documents that contain (for example) JavaScript or execute an action when opened. PDFiD will also handle name obfuscation.

Although we did so in reverse-order, a good methodology to use something like `pdfid.py` first to triage PDF documents, and then analyze suspicious ones with pdf-parser.

As an example, let's run `pdfid.py` against the `Dropper.pdf` file:

```
python3 Tools/pdfid.py Dropper.pdf
```

![pdfid output](https://github.com/user-attachments/assets/face5997-9b7c-4b86-9524-1ee2f9ee5d0e)

As suspected, the output provides an overview of the structure and various elements that make up the PDF. Commonly, we'll see structural objects or attributes like `xref`, `trailer`, and `startxref`, which are all core components used for file navigation. Additionally, we see `/Page`, which tells us how many pages are present in the document.

However, there are also a few potentially suspicious elements in our output as well, such as:

- `/JS` and `/JavaScript` indicate that the PDF contains embedded JavaScript, which could be used maliciously when opening a PDF in a web browser or client that executes JS.
- `/OpenAction` indicates that the PDF will attempt to automatically execute an action when the PDF is opened.
- `/EmbeddedFile` indicates that the PDF includes an embedded file, which *could* be a technique for delivering a malicious payload.

Because we've identified some suspicious indicators in this file, let's return to `pdf-parser.py` to analyze these objects.

## Embedded JavaScript

To extract any embedded JavaScript objects, we can call `pdf-parser.py`, provide the `-s` argument, and search for the `/JavaScript` string:

```
python3 Tools/pdf-parser.py Dropper.pdf -s "/JavaScript"
```

![pdf-parser.py output](https://github.com/user-attachments/assets/efdd9131-af6b-4fbd-9198-a5646e3c67a6)

By extracting any `/JavaScript` objects, we can identify that the PDF contains JavaScript embedded within an `/Action` object (`object 9`). Specifically, the JavaScript code is calling the `this.exportDataObject` method to extract or export an embedded file (`eicar-dropper.doc`) from the PDF. 

After doing so, it calls `nLaunch: 2` to direct Acrobat to save the file attachment to a temporary file and then ask the operating system to open it. More information on understanding these methods can be found [here](https://acrobatusers.com/tutorials/print/importing-and-exporting-pdf-file-attachments-acrobat-javascript/).

To conclude, it seems likely that this PDF is weaponized to deliver a file via JavaScript. Although its behavior and success depends on user interaction and the PDF reader's configuration, it's a clear indicator of something suspicious going on.

## Open Actions
Next, let's correlate our findings with any embedded open actions. To do so, we can run the same command as we did previously, but search for any `/OpenAction` objects:

```
python3 Tools/pdf-parser.py Dropper.pdf -s "/OpenAction"
```

![pdf-parser.py output](https://github.com/user-attachments/assets/364a5af1-53e3-4dc8-a003-54bc446473ae)

This appears to correlate with what we identified in the embedded JavaScript. When the PDF is opened, the `/OpenAction` triggers `object 9 0`, which we know from the earlier output contains JavaScript to extract and possibly execute the embedded file `eicar-dropper.doc`.

## Embedded Files
Lastly, let's attempt to extract the embedded `eicar-dropper.doc` file that we have seen referenced throughout the structure of this PDF. First, we can search for the `/EmbeddedFile` object to identify what object index it relates to:

```
python3 Tools/pdf-parser.py Dropper.pdf -s "/EmbeddedFile"
```

![pdf-parser.py output](https://github.com/user-attachments/assets/4dd150e0-ea02-4c64-ac53-d3fa7890c397)

From this output, we can see that the `eicar-dropper.doc` file is directly stored as an `/EmbeddedFile` (`obj 8 0`).

Now that we know the object index number (`8`), we can use the `--object` argument to select it, the `--filter` argument to decode the file, the `--raw` argument to write the output, and `--dump` to specify the filename to dump the file contents to: 

```
python3 Tools/pdf-parser.py Dropper.pdf --object 8 --filter --raw --dump eicar-dropper.doc
```

![pdf-parser.py output](https://github.com/user-attachments/assets/31f98669-8d39-40b9-ae1f-99bcc9f54201)

Excellent! We now have our hands on the embedded file and can begin to perform all sorts of additional static and dynamic analysis on it (such as looking up its hash and comparing it to threat intelligence databases, using tools like `oledump` to parse through any additional macros or scripts, or submit the file to a dynamic malware analysis solution like *Any.run* or *JoeSandbox*).

For example, by running the `md5sum` command, we can extract the file's MD5 hash value:

```
md5sum eicar-dropper.doc
```

![md5sum output](https://github.com/user-attachments/assets/79df3825-d96e-4fdb-aeb5-742e1b91c208)

By submitting this hash to [VirusTotal](https://virustotal.com) (`9b74140a678d813d6dd6de3708398194`), we'll find that several vendors have flagged this file as malicious (although, don't worry - it's just a test file).

![VirusTotal output](https://github.com/user-attachments/assets/37723c67-f616-4e31-bca4-2c32e3b109bf)


## Conclusion
Great work! We were able to securely extract the attachment from the email and use basic static analysis techniques to parse through multiple PDF files. By doing so, we were able to understand how to quickly extract URLs, search for risky objects, and document a number of malicious indicators.

## Indicators of Compromise
It's always a good idea to document the malicious artifacts we gathered during our investigation. Below, I have done so in *defanged* format. Defanging is a way to alter potentially dangerous URLs, IP addresses, and file paths to prevent them from being clickable or accidentally executed.

### Email Address
- `report-ppvguaohyzdqqtvec@wirangjos[.]clicklifestyles[.]com`

### Files
- `Tax_Report[.]pdf`
  - MD5: `9080bf37c122cdd9d4eb9e87e95ba614`
  - SHA1: `fe65064ac58658c1941cc12c43ccc7c8beff8afb`
  - SHA256: `c33f67a18ad931a7ae9957fc79e304178c7fa450aa471c544139018c45aad083`
- `Statement[.]pdf`
  - MD5: `14a3bf6d25308c6c320bcb328e71f189`
  - SHA1: `8e48b75a302674c28650ce63a4a669ae9525e235`
  - SHA256: `e90e263bce015c0ad6640d2581582aee4f940accc18d688a25d9a319e39c4110`
- `Dropper[.]pdf`
  - MD5: `a1ddc9ebe19a3d43ec25889085ad3ed8`
  - SHA1: `0fa681a24df1b6ee6960bf1098af9689cfb8a576`
  - SHA256: `86a96ec03ba8242c1486456d67ee17f919128754846dbb3bdf5e836059091dba`
- `eicar-dropper[.]doc`
  - MD5: `9b74140a678d813d6dd6de3708398194`
  - SHA1: `1a78759f1370cbe5efa82c2f03e523aa9bee299c`
  - SHA256: `eb0ae2d1cd318dc1adb970352e84361f9b194ff14f45b0186e4ed6696900394a`

### URLs
- `hxxps[://]monitor[.]clickcease[.]com`
- `hxxps[://]ecy[.]wcs520[.]com/wp-content/themes/evita/red[.]php`
- `hxxps[://]script[.]google[.]com/macros/s/AKfycbwABk1V3TSZ7dwG4lOsmbewJuEt2TExXS8cSaYuhcQwcxoffsDSJS8VLFR4h0pkJFwkUQ/exec`

## TCM Security
![TCM Security logo](https://github.com/user-attachments/assets/90283a54-d164-4990-a09b-4edb84ac661e)

If you enjoyed this scenario and lesson, be sure to check out TCM Security's [Security Operations (SOC) 101](https://academy.tcm-sec.com/p/security-operations-soc-101), a 30+ hour training course that dives deep into Phishing Analysis, Network Traffic Analysis, Endpoint Detection and Response, Log Analysis and Management, Security Information and Event Management (SIEM), Threat Intelligence, and DFIR operations. 😎🛡️
