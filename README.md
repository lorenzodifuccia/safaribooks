# SafariBooks
Download and read in EPUB your favorites books from [Safari Books Online](https://www.safaribooksonline.com).

## Usage:
```bash
~$ python3 safaribooks.py --cred "account_mail@mail.com:password01" XXXXXXXXXXXXX
```
The book ID (the X-es) are the digits that you can find in the URL.  
Ex: `https://www.safaribooksonline.com/library/view/book-name/XXXXXXXXXXXXX/ch01.html`  
  
The first time you use the program, you have to specify your SafariBooksOnline account credentials. 
Next times you want to download a book, before session expires, you can omit the credential because the program save your session cookies in a file called `cookies.json`.  
Pay attention if you use a shared PC, because everyone that has access to your files can steal your session. 
If you don't want to cache the cookies, just use the `--no-cookies` option and provide all the time your `--cred`. 

#### List of program option:
```text
usage: safaribooks.py [--cred <EMAIL:PASS>] [--no-cookies] [--preserve-log] [--help] <BOOK ID>

Download and read in EPUB your favorites books from Safari Books Online.

positional arguments:
  <BOOK ID>            Book digits ID that you want to download. You can find it in the URL (X-es):
                       `https://www.safaribooksonline.com/library/view/book-name/XXXXXXXXXXXXX/cover.html`

optional arguments:
  --cred <EMAIL:PASS>  Credentials used to perform the login on SafariBooksOnline.
                       Es. ` --cred "account_mail@mail.com:password01" `.
  --no-cookies         Prevent your session data to be saved into `cookies.json` file.
  --preserve-log       Leave the `info.log` file even if there isn't any error.
  --help               Show this help message.
```

## Example:
\# TODO
