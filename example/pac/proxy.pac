function isMatchProxy(url, pattern) {
    try {
        return new RegExp(pattern.replace('.', '.')).test(url);
    } catch (e) {
        return false;
    }
}

function FindProxyForURL(url, host) {
    var Proxy = 'PROXY 192.168.1.10:1898; DIRECT';
    var list = [
            't.co',
            'twitter.com',
            'twimg.com',
            'posterous.com',
            'tinypic.com',
            'twitpic.com',
            'bitly.com',
            'yfrog.com',
            'youtube.com',
            'facebook.com',
            'appspot.com',
            'dropbox.com',
            'flickr.com',
            'youtube.com',
            'ytimg.com',
            'plus.google.com',
            'ggpht.com',
            'talkgadget.google.com',
            'picasaweb.google.com',
            'googleusercontent.com',
            'hzmangel.info',
            'slideshare.net',
            'code.google.com',
            'golang.org',
            'vimeo.com',
            'wordpress.com',
            'dxtl.net',
            '123cha.com',
            "yimg.com",
        ];
    for(var i=0, l=list.length; i<l; i++) {
        if (isMatchProxy(url, list[i])) {
            return Proxy;
        }
    }

    return 'DIRECT';
}
