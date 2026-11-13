#!/bin/bash

cd /home/re/Desktop/SpaghettiHacker/spaghetti-hacker.github.io/ 

cp news_db.json ./news_db_vecchio.json

python3 news_fetcher.py

mv news_db.json ./news_db_nuovo.json

jq -s --arg cutoff "$(date -d '7 days ago' +%F)" '
  { updated: .[1].updated, window_days: 7,
    items: ( (.[0].items + .[1].items)
      | group_by(.sources[0].url) | map(last)
      | map(select(.published >= $cutoff))
      | group_by(.published) | reverse
      | map( to_entries | map(.value + {id: (.value.published + "-" + ("00" + ((.key+1)|tostring))[-3:])}) )
      | add ) }
' news_db_vecchio.json news_db_nuovo.json > news_db.json
