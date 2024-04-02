# Diane

Diane is a fuzzer designed for IoT devices. It functions by identifying fuzzing triggers within IoT companion apps to generate valid yet under-constrained inputs. Our key insight is the presence of functions within these apps that execute after input validation but before data-transforming functions like network serialization.

## Repository structure
```bash
diane/
│
├── __init__.py
├── fuzzcounter.py
├── requirements.txt
├── run.py
│
└── src/
    │
    ├── __init__.py
    ├── arg_fuzzer/
    │   │
    │   ├── __init__.py
    │   ├── arg_fuzzer.py
    │   ├── arg_values/
    │   │   │
    │   │   ├── __init__.py
    │   │   ├── formatted_values.py
    │   │   ├── keyhunter/
    │   │   │   │
    │   │   │   ├── __init__.py
    │   │   │   ├── ida_extract_keys.py
    │   │   │   ├── key_hunter.py
    │   │   │   ├── key_strings.txt
    │   │   │   ├── tests/
    │   │   │   │   │
    │   │   │   │   ├── 01/
    │   │   │   │   │   │
    │   │   │   │   │   ├── Makefile
    │   │   │   │   │   ├── out/
    │   │   │   │   │   │   │
    │   │   │   │   │   │   ├── test01
    │   │   │   │   │   │   │
    │   │   │   │   │   │   └── test01.c
    │   │   │   │   │   │
    │   │   │   │   │   └── out/
    │   │   │   │   │
    │   │   │   │   └── __init__.py
    │   │   │   │
    │   │   │   └── utils.py
    │   │   │
    │   │   ├── pcapreader/
    │   │   │   │
    │   │   │   ├── __init__.py
    │   │   │   ├── http.py
    │   │   │   ├── pcapreader.py
    │   │   │   └── usage.py
    │   │   │
    │   │   └── random_values.py
    │   │
    │   └── values.py
    │
    ├── crash_detector/
    │   │
    │   ├── __init__.py
    │   ├── base_detector.py
    │   ├── pcap_analysis/
    │   │   │
    │   │   ├── __init__.py
    │   │   │
    │   │   └── pcap_base_detector.py
    │   │
    │   └── __init__.py
    │
    ├── frida_hooker/
    │   │
    │   ├── __init__.py
    │   ├── base_script.js
    │   ├── exports.js
    │   ├── frida_hooker.py
    │   └── object_setter.js
    │
    ├── methods_finder/
    │   │
    │   ├── __init__.py
    │   ├── clusterizer/
    │   │   │
    │   │   ├── __init__.py
    │   │   └── clusterizer.py
    │   │
    │   ├── send_finder.py
    │   └── sweet_spot_finder.py
    │
    ├── node_filter/
    │   │
    │   ├── __init__.py
    │   └── node_filter.py
    │
    ├── sanity_check/
    │   │
    │   ├── helper.py
    │   ├── run_worker.sh
    │   ├── sanity_check.py
    │   ├── schedule_on_celery.py
    │   ├── setup_env.sh
    │   ├── viewer.py
    │   └── worker.py
    │
    ├── sniffer/
    │   │
    │   ├── __init__.py
    │   ├── bltlog_analyzer.py
    │   ├── dump_to_pcap.sh
    │   ├── sniff.sh
    │   └── sniffer.py
    │
    └── ui/
        │
        ├── __init__.py
        ├── config.py
        ├── core.py
        ├── README.md
        └── RERAN/
            │
            ├── replay
            └── translate.jar

```
##Dependencies

To run Diane successfully, ensure you have the following dependencies installed:

- Python 3.6 or higher
- Frida 14.0.18 or higher
- PySoot 0.1.2 or higher
- PyShark 0.4.4 or higher
- ADB (Android Debug Bridge)

You can install the required Python packages using pip:

```bash
pip install -r requirements.txt 
```

## Configuration

Before running Diane, configure the `config.py` file with the correct paths and settings. The crucial settings include:

- `apk_path`: Path to the companion app APK file.
- `device_id`: ID of the Android device running the companion app.
- `android_ip`: IP address of the Android device.
- `device_ip`: IP address of the IoT device.
- `ip_hot_spot`: IP address of the Wi-Fi hotspot created by the IoT device.
- `pass_ap`: Password for the Wi-Fi hotspot created by the IoT device.
- `leaf_pickle`: Path to the pickle file containing pre-generated leaf nodes (optional).

## Running Diane

To execute Diane, run the `run.py` script with the path to the configuration file as an argument:

```bash
python run.py path/to/config.json
```

Diane will carry out the following steps:

1. Set up the environment and hook the companion app using Frida.
2. Identify potential fuzzing triggers in the app.
3. Analyze network traffic and cluster packets.
4. Generate under-constrained inputs for each fuzzing trigger.
5. Send the generated inputs to the IoT device and observe its behavior.

The results of the fuzzing process will be saved in the output directory.

## Research Paper

Our approach and findings are detailed in the research paper:

**DIANE: Identifying Fuzzing Triggers in Apps to Generate Under-constrained Inputs for IoT Devices**  
[PDF](link-to-your-pdf)

*Nilo Redini, Andrea Continella, Dipanjan Das, Giulio De Pasquale, Noah Spahn, Aravind Machiry, Antonio Bianchi, Christopher Kruegel, Giovanni Vigna.*  
*In Proceedings of the IEEE Symposium on Security & Privacy (S&P), May 2021*

If you utilize Diane in a scientific publication, we kindly request citations using the following Bibtex entry:

```bibtex
@inproceedings{redini_diane_21,
 author = {Nilo Redini and Andrea Continella and Dipanjan Das and Giulio De Pasquale and Noah Spahn and Aravind Machiry and Antonio Bianchi and Christopher Kruegel and Giovanni Vigna},
 booktitle = {In Proceedings of the IEEE Symposium on Security & Privacy (S&P)},
 month = {May},
 title = {{DIANE: Identifying Fuzzing Triggers in Apps to Generate Under-constrained Inputs for IoT Devices}},
 year = {2021}
}
```

---

Please replace `link-to-your-pdf` in the research paper section with the actual link to your PDF file or provide instructions for accessing it.
