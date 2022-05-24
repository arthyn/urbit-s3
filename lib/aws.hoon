=,  scr:crypto
|_  [reg=@t secret=@t key=@t now=@da]
+$  purl  purl:eyre
::  ++ auth will apply all required headers for signature v4 to
::  whatever request you pass it
::
::  the headers are: 
::  authorization, x-amz-content-sha256, x-amz-date
::
::  The basic process for signature v4 is as follows:
::  - ++ canonical: produce canonical request
::  - create a hash digest of the canonical request
::  - ++ contract: put together a "string to sign", using ++ scope and
::    hash digest
::  - ++ signer: create a signing key, using repeated HMACs
::  - ++ sign: generate signature for authorization header
::  - ++ cred: produce full authorization header, including Credential,
::    SignedHeaders, and Signature
::
::  https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
::
++  auth
  |=  =request:http
  ^-  request:http
  =.  header-list.request
    (cred request)
  request
::  ++ auth-dbg is useful for debugging intermediate steps for auth
++  auth-dbg
  |=  =request:http
  =/  bod       (pile body.request)
  =.  header-list.request   (attach header-list.request 'x-amz-content-sha256' bod)
  =.  header-list.request   (attach header-list.request 'x-amz-date' (crip clock))
  =/  canonical  (canonical request)
  =/  digest  (hash (crip canonical))
  =/  contract  (contract request digest)
  :*  canonical=canonical 
      digest=digest 
      contract=contract 
      signer=(en:base16:mimes:html 32 signer)
      sign=(sign contract)
  ==
++  cred
  |=  =request:http
  ^-  header-list:http
  =/  bod       (pile body.request)
  =.  header-list.request   (attach header-list.request 'x-amz-content-sha256' bod)
  =.  header-list.request   (attach header-list.request 'x-amz-date' (crip clock))
  %^  attach  header-list.request
    'Authorization'
  %-  crip
  %+  weld
    "AWS4-HMAC-SHA256 "
  ^-  tape
  %-  zing  
  %+  join
    ", "
  ^.  (list tape)
  :~  ;:  weld
          "Credential="
          (trip key)
          "/"
          scope
      ==
      %+  weld
          "SignedHeaders="
          %-  facet
            +:(crest header-list.request)
      %+  weld
          "Signature="
          %-  trip
            %-  sign
          %+  contract
            request
          %-  hash
            %-  crip
          (canonical request)
  ==
++  sign
  |=  deal=@t
  %+  en:base16:mimes:html  32 
  (hmc signer deal)
++  signer
  %+  hmc
    %+  hmc
      %+  hmc
        %+  hmc
          (crip (weld "AWS4" (trip secret)))
        (crip cal)
      reg
    's3'
  'aws4_request'
++  contract
  |=  [=request:http digest=@t]
  ^-  @t
  =/  hydra=(map @t @t)  (malt header-list.request)
  %-  crip
  %+  weld
    %+  roll
      ^-  (list tape)
      :~  "AWS4-HMAC-SHA256"
          %-  trip
            %+  ~(gut by hydra)
              'x-amz-date'
            (crip clock)
          scope
      ==
    link
  (trip digest)
++  scope
  ^-  tape
  %+  join  '/'
    ^-  (list @t)
    :~  (crip cal)
        reg
        's3'
        'aws4_request'
    ==  
++  canonical
  |=  =request:http
  =/  url=purl  (need (de-purl:html url.request))
  =/  crown     (crest header-list.request)
  %+  weld
    %+  roll
      ^-  (list tape)
      :~  `tape`[method.request ~]
          (trail url)
          (quiz url)
          -.crown
          (facet +.crown)
      ==
    link
  (trip (pile body.request))
::  concatenate two tapes and stick a newline on the end
++  link
  |=  [item=tape pole=tape]
  ^-  tape
  (weld pole (snoc item '\0a'))
::  grab the URL path and encode the parts
++  trail
  |=  url=purl
  ^-  tape
  =/  parts=(list tape)  (turn q.q.url trip)
  =/  road=tape  `tape`(zing (join "/" `(list tape)`(turn parts en-urlt:html)))
  (weld ~['/'] road)
::  sort the query parameters by key, url encode both key and value,
::  join each together with '&' and weld the whole thing into a tape
++  quiz
  |=  url=purl
  =/  quay  r.url
  ^-  tape
  ?~  quay  ""
  =/  squr  %+  sort  quay
  |=  [a=[@t @t] b=[@t @t]]
  (gth -.a -.b)
  =/  tqur  %+  turn  squr
  |=  item=[@t @t]
  :(weld (en-urlt:html (trip -.item)) "=" (en-urlt:html (trip +.item)))
  %+  roll  `(list tape)`(join "&" tqur)
  |=  [item=tape pole=tape]
  (weld pole item)
::  lowercase the header keys, trim leading/trailing whitespace and
::  repeated whitespace in values, join key and value with ':', and add
::  a newline after each header
++  crest
  |=  heads=header-list:http
  =/  hydra=(map @t @t)  (malt heads)
  %+  ~(rib by hydra)  *tape
    |=  [[k=@t v=@t] acc=tape]
    =/  key=tape    (cass (trip k))
    =/  value=tape  (trimall v)
    =/  combo=tape  (weld (snoc key ':') value)
    :-  (link combo acc) 
      [(crip key) (crip value)]
::  grab list of header keys, sort them, and join with ';'
++  facet
  |=  heads=(map @t @t)
  ^-  tape
  =/  hydra=(list @t)  `(list @t)`~(tap in ~(key by heads))
  (join ';' (sort hydra aor))
::  hash an octs
++  pile
  |=  body=(unit octs)
  ^-  @t
  %-  hash
  ?~  body  ''  
    +:(need body)
::  sha256 with correct byte ordering and hex encoded
++  hash
  |=  content=@t
  ^-  @t
  %+  en:base16:mimes:html  32 
  %^  rev  3
      32
  (shax content)
::  add header to header-list
++  attach
  |=  [top=header-list:http key=@t value=@t]
  ^-  header-list:http
  =/  hydra  (malt top)
  %~  tap  by
  %+  ~(put by hydra)
    key
  value
::  trim leading and trailing whitespace, replace repeated whitespace
::  with single whitespace
++  trimall
  |=  value=@t
  |^  ^-  tape
  %+  rash  value
  %+  ifix  [(star ws) (star ws)]
  %-  star
  ;~  less
    ;~(plug (plus ws) ;~(less next (easy ~)))
    ;~(pose (cold ' ' (plus ws)) next)
  ==
  ++  ws  (mask " \0a\0d\09")
  --
::  formatted date
++  cal
  (swag [0 8] clock)
::  formatted datetime
++  clock
  (esoo now)
::  ISO8601 date
::
++  esoo
  |=  d=@d
  ^-  tape
  =/  t  (yore d)
  ;:  welp
      (scag 1 (scow %ud y.t))
      (swag [2 3] (scow %ud y.t))
      (double m.t)
      (double d.t.t)
      "T"
      (double h.t.t)
      (double m.t.t)
      (double s.t.t)
      "Z"
  ==
:: ud to leading zero tape
++  double
  |=  a=@ud
  ^-  tape
  =/  x  (scow %ud a)
  ?:  (lth a 10)
    (welp "0" x)
  x
--