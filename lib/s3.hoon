/+  aws
=,  scr:crypto
|_  [endpoint=@t reg=@t secret=@t key=@t now=@da]
+$  purl  purl:eyre
++  aws-client  ~(. aws [reg secret key now])
::  a minimal support version of ListObjectsV2
::  https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
++  s3-list-objects-v2
  |=  bucket=@t
  =/  url=purl  (need (de-purl:html endpoint))
  %-  auth:aws-client
  :^    %'GET'
      %-  crip
        %-  en-purl:html
          =:  q.url  [~ ~[bucket]]
              r.url  :~(['list-type' '2'])
          ==
        url
    :~  :-  'Host'
      %-  crip
        %+  scan  (head:en-purl:html p.url)
        ;~(pfix (jest 'https://') (star prn))
    ==
  ~
--