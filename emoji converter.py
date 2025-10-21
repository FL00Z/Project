def emoji_converter(message):
    words = message.split(" ")
    emojis = { # Dictionary to store emojis with their corresponding text symbols
   
    ":)": "😊",  # Happy face
    ":(": "😢"   # Sad face
    }
    output=""
    for word in words:
        output += emojis.get(word, word)+ " "
    return output


message= input("> ")
print(emoji_converter(message))   
