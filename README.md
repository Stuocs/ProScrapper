**Tracker and Executable Analysis Tool**

This repository provides a Python-based tool for detecting web trackers on URLs and analyzing Windows executables for network-related imports. It features caching, logging, honeypot-based IP registration, Selenium fallback, and a simple Tkinter GUI.

---

## Features

1. **Web Tracker Detection**

   * Caches previous results to avoid redundant requests.
   * Performs HTTP GET requests with exponential backoff.
   * Falls back to headless Selenium for dynamic content.
   * Detects known trackers (that you can update) via script inspection.
   * Flags: cookies, canvas fingerprinting, and CNAME cloaking.
   * Honeypot endpoints to register suspicious IPs.

2. **Executable Network-Import Analysis**

   * Provides a file-selection dialog (Tkinter) for `.exe` files.
   * Parses the PE format using `pefile`.
   * Identifies imports related to networking (e.g., `connect`, `socket`, `WinHttpSendRequest`, etc.).
   * Enriches findings with human-readable descriptions from JSON.

3. **Honeypot IP Registration**

   * Predefined honeypot endpoints to catch suspicious connections.
   * Extracts client IPs and logs them with timestamps.
   * Stores in `cache_honeypot.json`.
   * This one can not work properly depending of the version.

4. **Caching and Logging**

   * Results of URL analysis saved in `cachevisita.json`.
   * Honeypot IPs saved in `cache_honeypot.json`.
   * All events and errors logged to `Tracking.log`.

5. **User Interface (Tkinter)**

   * Simple GUI with:

     * URL input and "Analyze URL" button
     * "Analyze Executable" button
     * Scrollable text area for results
   * Dark-themed result window (black background, green text).

---

## Requirements

* Python 3.8+
* Google Chrome installed (for Selenium)
* Dependencies listed in `requirements.txt`:

  ```
  requests
  selenium
  webdriver-manager
  beautifulsoup4
  pefile
  dnspython
  tkinter
  ```

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/ProScrapper.git
   cd ProScrapper
   ```
2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate    # Linux/macOS
   venv\\Scripts\\activate   # Windows
   ```
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## Configuration

* **Known Trackers**: Edit `rastreadores_conocidos.json` to add or remove tracker signatures.
* **Function Descriptions**: Update `descripciones_funciones.json` with descriptions for additional imports.
* **Honeypot Endpoints**: Modify the `honeypot_endpoints` list in the script.

---

## Usage

Run the main script:

```bash
python main_script.py
```

1. **Analyze a URL**:

   * Enter the target URL (e.g., `https://example.com`).
   * Click **Analyze URL**.
   * Results display detected trackers or indicate none found.

2. **Analyze a Windows executable**:

   * Click **Analyze Executable**.
   * Select a `.exe` file.
   * View detected network imports and their descriptions.

---

## Logging

* Logs stored in `Tracking.log` (INFO level).
* Includes timestamps, warnings, and error messages.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Implement changes and add tests.
4. Submit a pull request.
