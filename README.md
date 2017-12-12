# SafariBooks
Download and generate an EPUB of your favorite books from [Safari Books Online](https://www.safaribooksonline.com) library.  
Use this program only for personal and/or educational purpose.  

## Requirements & setup:
```shell
$ git clone https://github.com/lorenzodifuccia/safaribooks.git
Cloning into 'safaribooks'...

$ cd safaribooks/
$ pip3 install -r requirements.txt
```  

The program depends of only two Python 3 modules:
```python3
lxml>=4.1.1
requests>=2.18.4
```
  
## Usage:
It's really simple to use, just choose a book from the library and replace in the following command:
  * X-es with its ID, 
  * `email:password`  with your own. 

```shell
$ python3 safaribooks.py --cred "account_mail@mail.com:password01" XXXXXXXXXXXXX
```

The ID are the digits that you can find in the URL of the book description page:  
`https://www.safaribooksonline.com/library/view/book-name/XXXXXXXXXXXXX/`  
Like: `https://www.safaribooksonline.com/library/view/test-driven-development-with/9781491958698/`  
  
The first time you'll use the program, you'll have to specify your Safari Books Online account credentials. 
For the next times you'll download a book, before session expires, you can omit the credential, because the program save your session cookies in a file called `cookies.json`.  
  
Pay attention if you use a shared PC, because everyone that has access to your files can steal your session. 
If you don't want to cache the cookies, just use the `--no-cookies` option and provide all the time your `--cred`.  

The program default options are thought for ensure best compatibilities for who want to export the `EPUB` to E-Readers like Amazon Kindle.  
If you want to do it, I suggest you to convert the `EPUB` to `AZW3` file with [Calibre](https://calibre-ebook.com/).  
You can also convert the book to `MOBI` and if you'll convert it with Calibre be sure to select `Ignore margins`:  
  
![Calibre IgnoreMargins](https://github.com/lorenzodifuccia/cloudflare/raw/master/Images/safaribooks/safaribooks_calibre_IgnoreMargins.png "Select Ignore margins")  
  
### Program options:
```shell
$ python3 safaribooks.py --help
usage: safaribooks.py [--cred <EMAIL:PASS>] [--no-cookies] [--no-kindle]
                      [--preserve-log] [--help]
                      <BOOK ID>

Download and generate an EPUB of your favorite books from Safari Books Online.

positional arguments:
  <BOOK ID>            Book digits ID that you want to download.
                       You can find it in the URL (X-es):
                       `https://www.safaribooksonline.com/library/view/book-
                       name/XXXXXXXXXXXXX/`

optional arguments:
  --cred <EMAIL:PASS>  Credentials used to perform the auth login on Safari
                       Books Online.
                       Es. ` --cred "account_mail@mail.com:password01" `.
  --no-cookies         Prevent your session data to be saved into
                       `cookies.json` file.
  --no-kindle          Remove some CSS rules that block overflow on `table`
                       and `pre` elements. Use this option if you're not going
                       to export the EPUB to E-Readers like Amazon Kindle.
  --preserve-log       Leave the `info.log` file even if there isn't any
                       error.
  --help               Show this help message.
```

  * ## Example: [Test-Driven Development with Python, 2nd Edition](https://www.safaribooksonline.com/library/view/test-driven-development-with/9781491958698/)  
    ```shell
    $ python3 safaribooks.py --cred "XXXX@gmail.com:XXXXX" 9781491958698

           ____     ___         _ 
          / __/__ _/ _/__ _____(_)
         _\ \/ _ `/ _/ _ `/ __/ / 
        /___/\_,_/_/ \_,_/_/ /_/  
          / _ )___  ___  / /__ ___
         / _  / _ \/ _ \/  '_/(_-<
        /____/\___/\___/_/\_\/___/

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    [-] Logging into Safari Books Online...                                         
    [-] Title: Test-Driven Development with Python, 2nd Edition                     
    [-] Authors: Harry J.W. Percival                                                
    [-] Identifier: 9781491958698                                                   
    [-] ISBN: 9781491958704                                                         
    [-] Publishers: O'Reilly Media, Inc.                                            
    [-] Rights: Copyright © O'Reilly Media, Inc.                                    
    [-] Description: By taking you through the development of a real web application from beginning to end, the second edition of this hands-on guide demonstrates the practical advantages of test-driven development (TDD) with Python. You’ll learn how to write and run tests before building each part of your app, and then develop the minimum amount of code required to pass those tests. The result? Clean code that works.In the process, you’ll learn the basics of Django, Selenium, Git, jQuery, and Mock, along with curre...
    [-] URL: https://www.safaribooksonline.com/library/view/test-driven-development-with/9781491958698/
    [*] Found 73 chapters!                                                          
    [*] Output directory:                                                           
        /XXXX/XXXX/Test-Driven Development with Python, 2nd Edition
    [-] Downloading book contents...                                                
        [#########################################----------------------------]  60%
    ...
    [-] Creating EPUB file...                                                       
    [*] Done: Test-Driven Development with Python, 2nd Edition.epub                 

        If you like it, please * this project on GitHub to make it known:
            https://github.com/lorenzodifuccia/safaribooks
        e don't forget to renew your Safari Books Online subscription:
            https://www.safaribooksonline.com/signup/

    [!] Bye!!
    ```  
     The result will be (opening the `EPUB` file with Calibre):  

    ![Book Appearance](https://github.com/lorenzodifuccia/cloudflare/raw/master/Images/safaribooks/safaribooks_example01_TDD.png "Book opened with Calibre")  
 
  * ## Example: `--no-kindle` option
    ```bash
    $ python3 safaribooks.py --no-kindle 9781491958698
    ```  
    ![NoKindle Option](https://github.com/lorenzodifuccia/cloudflare/raw/master/Images/safaribooks/safaribooks_example02_NoKindle.png "Version comparison")  
