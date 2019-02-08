#!/usr/bin/python2.7

import requests
import time
#import datetime

url = "https://api.telegram.org/bot517751436:AAF7G921SsocmbiJ17CSoDOTbrGrKwEvlE0/"

def get_updates_json(request):  
    response = requests.get(request + 'getUpdates')
    return response.json()
 
 
def last_update(data):  
    results = data['result']
    total_updates = len(results) - 1
    return results[total_updates]

def get_chat_id(update):  
    chat_id = update['message']['chat']['id']
    return chat_id
 
def send_mess(chat, text):  
    params = {'chat_id': chat, 'text': text}
    response = requests.post(url + 'sendMessage', data=params)
    return response
 
chat_id = get_chat_id(last_update(get_updates_json(url)))
 
send_mess(chat_id, 'NACHAUTObot started')


def main():

    taken=0
    price=0.045
    l_update = last_update(get_updates_json(url))
    update_id = l_update['update_id']
  
    while True:
        l_update = last_update(get_updates_json(url))

        last_update_id = l_update['update_id']
        last_chat_text = l_update['message']['text'].split()
        last_chat_id = l_update['message']['chat']['id']
        last_chat_name_id = l_update['message']['from']['id']
        last_chat_name = l_update['message']['from']['first_name']

        if update_id == last_update_id:
            if last_chat_text[0].lower() == "take":
                if not taken:
                    try:
                        send_mess(get_chat_id(last_update(get_updates_json(url))), last_chat_text[1]+' taken by '+last_chat_name+' ('+str(last_chat_name_id)+')')
                        taken=1
                        taken_time=time.time()
                        taken_item=last_chat_text[1]
                    except:
                        send_mess(get_chat_id(last_update(get_updates_json(url))), last_chat_name+' '+str(last_chat_name_id)+', please, specify car number plate in take request.')
                else:
                        send_mess(get_chat_id(last_update(get_updates_json(url))), last_chat_name+' '+str(last_chat_name_id)+', only 1 car could be taken')
            if last_chat_text[0].lower() == "return":
                if taken:
                    try:
                        if (last_chat_text[1] == taken_item): 
                            send_mess(get_chat_id(last_update(get_updates_json(url))), last_chat_text[1]+' returned by '+last_chat_name+' ('+str(last_chat_name_id)+')')
                            taken=0
                            return_time=time.time()
                            payment=price*(return_time-taken_time)
			    send_mess(get_chat_id(last_update(get_updates_json(url))), last_chat_name+', you shoud pay for the rent '+str(round(payment,2))+' rub for '+str(return_time-taken_time)+' sec')
                        else:
                            send_mess(get_chat_id(last_update(get_updates_json(url))), last_chat_name+', you could return only what you had taken')


                    except:
                        send_mess(get_chat_id(last_update(get_updates_json(url))), last_chat_name+' '+str(last_chat_name_id)+', please, specify car number plate in take request.')
                else:
                        send_mess(get_chat_id(last_update(get_updates_json(url))), last_chat_name+' '+str(last_chat_name_id)+', only 1 car could be taken at a time')
            if last_chat_text[0].lower() == "exp":
                if taken:
                    send_mess(get_chat_id(last_update(get_updates_json(url))), str(round((time.time()-taken_time)*price,2))+' rub')
                else:
                    send_mess(get_chat_id(last_update(get_updates_json(url))), '0 rub')



            #send_mess(get_chat_id(last_update(get_updates_json(url))), update_id)
            update_id += 1
        time.sleep(5)
        #if update_id == last_update(get_updates_json(url))['update_id']:
        #   send_mess(get_chat_id(last_update(get_updates_json(url))), 'test')
        #   update_id += 1
        #sleep(5)       
 
if __name__ == '__main__':  
    main()
