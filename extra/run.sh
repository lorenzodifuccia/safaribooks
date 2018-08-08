#!/bin/sh
KINDLE="false"

usage(){
  echo "docker run --it -rm -e EMAIL='my@email' -e PASSWORD='mypass' -e BOOKID='111' -v /my/books:/app/converted:Z <image> [--kindle]"
  echo "  EMAIL     Your Safaribooks email"
  echo "  PASSWORD  Your Safaribooks password"
  echo "  BOOKID    Book digits ID that you want to download."
  echo "            You can find it in the URL (X-es):"
  echo "            ../library/view/book-name/XXXXXXXXXXXXX/"
  echo "  --kindle  Create also kindle formated ebook"
}

while [ "$1" != "" ]; do
    PARAM=`echo $1 | awk -F= '{print $1}'`
    case $PARAM in
        -h | --help)
            usage
            exit 1
            ;;
        -k | --kindle)
            KINDLE="true"
            ;;
        *)
            echo "ERROR: unknown parameter \"${PARAM}\""
            usage
            exit 1
            ;;
    esac
    shift
done

python3 /app/safaribooks.py \
  --cred "${EMAIL}:${PASSWORD}" \
  --no-cookies ${BOOKID} || exit 2
mv Books/*/*.epub /app/converted/

if [ ${KINDLE} = "true" ]; then
  /app/kindlegen /app/converted/*.epub
fi
