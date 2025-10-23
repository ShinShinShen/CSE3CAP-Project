# Firefind-Firewall

This program is built purely on Python, you will need a modern version of Python to run it. The only third-party dependencies are a few python libraries.

## Dependencies

This project requires the following Python libraries:

- [pandas](https://pandas.pydata.org/) — for data processing and analysis  
- [openpyxl](https://openpyxl.readthedocs.io/) — for reading and writing (`.xlsx`) files  
- [fpdf2](https://py-pdf.github.io/fpdf2/) — for generating PDF reports 
- matplotlib — for generating severity distribution charts 


Note: Python 3.12 is highly recommended and will have the best compatibility.

## ⚙️ Installation & Setup
### 1. Clone the Repository
```bash
git clone git@github.com:ShinShinShen/Firefind-Firewall.git

cd Firefind-Firewall
```
## 2. Create a Virtual Environment
```bash
python3.12 -m venv .venv
```

*Entering the Virtual Environment*

**For Linux/Mac**
```bash
source .venv/bin/activate   
```
**For Windows**
```bash
.venv\Scripts\activate.bat    
```

## 3. Install Dependencies 

All dependencies are listed in the [`requirements.txt`] file.  

To install them into your environment, run:
(ensure you are in .venv virtual environment before installing dependencies and running the program)

```bash
pip install -r requirements.txt
```
The above will take care of any and all dependencies required for this project, installing them all for you in single command.





## 📜 License
This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.
