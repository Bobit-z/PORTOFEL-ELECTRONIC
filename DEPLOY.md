# Publicare Wallet EL online

Aplicatia poate rula pe un server Python fara instalari speciale. Dupa publicare, nu mai trebuie sa tii codul pornit pe calculatorul tau.

## Fisiere necesare

- `app.py`
- `Procfile`
- `requirements.txt`
- optional: `wallet_secure_data.json` daca vrei sa pornesti cu datele existente

## Rulare locala

```powershell
python app.py
```

Deschide:

```text
http://127.0.0.1:5000/
```

## Rulare pe server

Serverul trebuie sa porneasca:

```bash
python app.py
```

Aplicatia citeste automat variabila `PORT`, deci merge pe hostings care aloca port dinamic.

## Varianta recomandata

1. Creezi un cont pe un hosting Python.
2. Creezi un proiect nou de tip Web Service / Python app.
3. Incarci fisierele din acest folder.
4. Setezi comanda de pornire:

```bash
python app.py
```

5. Deschizi linkul public oferit de hosting.

Exemple de hosting potrivite:

- Render
- Railway
- PythonAnywhere
- un VPS propriu

## Observatie importanta

Aceasta este o aplicatie demo. Pentru productie reala:

- foloseste HTTPS
- foloseste baza de date, nu fisier JSON local
- nu stoca chei private reale pe server
- foloseste un wallet/provider real pentru tranzactii blockchain
- adauga backup si loguri
