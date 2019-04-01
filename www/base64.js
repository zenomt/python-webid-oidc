function Base64URL() {}

Base64URL.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

Base64URL.encode = function(arrayBuffer, pad) {
    var u8arr = new Uint8Array(arrayBuffer);
    var rv = [];
    var b;

    for(var x = 0; x < u8arr.length; x+= 3)
    {
        b = (u8arr[x] & 0xfc) >> 2;
        rv.push(Base64URL.alphabet[b]);

		b = (u8arr[x] & 0x03) << 4;
		if(x + 1 < u8arr.length)
		{
			b = b + ((u8arr[x + 1] & 0xf0) >> 4);
			rv.push(Base64URL.alphabet[b]);

			b = (u8arr[x + 1] & 0x0f) << 2;
			if(x + 2 < u8arr.length)
			{
				b = b + ((u8arr[x + 2] & 0xc0) >> 6);
				rv.push(Base64URL.alphabet[b]);
				b = u8arr[x + 2] & 0x3f;
				rv.push(Base64URL.alphabet[b]);
			}
			else
			{
				rv.push(Base64URL.alphabet[b]);
				if(pad)
					rv.push("=");
			}
		}
		else
		{
			rv.push(Base64URL.alphabet[b]);
			if(pad)
				rv.push("==");
		}
	}

	return rv.join("");
}

Base64URL.decode = function(str) {
	var codes = [];
	var rv = [];
	var x = 0;

	while(x < str.length)
	{
		var b = Base64URL.alphabet.indexOf(str[x++]);
		if(b >= 0)
			codes.push(b);
	}

	for(x = 0; x < codes.length; x += 4)
	{
		var b0 = codes[x];
		var b1 = codes[x + 1] || 0;
		var b2 = codes[x + 2] || 0;
		var b3 = codes[x + 3] || 0;

		var d0 = ((b0 << 2) + (b1 >> 4)) & 0xff;
		var d1 = ((b1 << 4) + (b2 >> 2)) & 0xff;
		var d2 = ((b2 << 6) + (b3     )) & 0xff;

		rv.push(d0);
		if(x + 2 < codes.length)
			rv.push(d1);
		if(x + 3 < codes.length)
			rv.push(d2);
	}

	return new Uint8Array(rv);
}

Base64URL.decodeUTF8String = function(str) {
	return new TextDecoder().decode(Base64URL.decode(str));
}
