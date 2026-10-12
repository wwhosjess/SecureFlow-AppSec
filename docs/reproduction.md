# Executable lab walkthrough

Use Python 3.12+ from the repository root. These steps exercise real HTTP behavior against synthetic local targets.

## Start the two modes

In separate terminals:

```powershell
python -m lab.app --mode vulnerable --port 5050
python -m lab.app --mode fixed --port 5051
```

Use an available port if either is occupied and update the commands below. Both services bind only to `127.0.0.1`.

## Establish identity and reproduce IDOR

```powershell
curl.exe -i http://127.0.0.1:5050/me
curl.exe -i http://127.0.0.1:5050/orders/1002
```

The first response identifies `alice`; the second returns HTTP 200 with Bob's order. Vulnerable mode has not authenticated Alice: `Shop.authenticate` trusts `X-User` or defaults to Alice. The order response's `owner_id` identifies the owner, not the requester.

```powershell
curl.exe -i -H "X-User: bob" http://127.0.0.1:5050/me
curl.exe -i -H "X-User: bob" http://127.0.0.1:5050/orders/1001
```

The service now claims Bob, but still returns Alice's order. Trusting the header is an authentication flaw; omitting the ownership check is a separate authorization flaw.

## Verify the fixed behavior

```powershell
$loginBody = @{username='alice'; password='demo-password'} | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:5051/login -Method Post -ContentType 'application/json' -Body $loginBody -SessionVariable aliceSession
Invoke-RestMethod http://127.0.0.1:5051/me -WebSession $aliceSession
try {
    Invoke-WebRequest -UseBasicParsing http://127.0.0.1:5051/orders/1002 -WebSession $aliceSession
} catch {
    if ($null -eq $_.Exception.Response) { throw }
    "HTTP $([int]$_.Exception.Response.StatusCode)"
    $_.ErrorDetails.Message
}
$own = Invoke-WebRequest -UseBasicParsing http://127.0.0.1:5051/orders/1001 -WebSession $aliceSession
$own.StatusCode
$own.Content
```

Fixed mode verifies the signed session: `/me` returns Alice, Bob's order returns **403**, and Alice's own order returns **200**. The same check works in reverse for Bob. A header alone is insufficient:

```powershell
curl.exe -i -H "X-User: bob" http://127.0.0.1:5051/me
```

This returns **401** without a valid cookie. `Shop.login` checks credentials and signs the session; `Shop.authenticate` verifies its signature and expiry; `Shop.order` checks resource ownership. Read [lab/app.py](../lab/app.py).

## Reproduce SQL injection

```powershell
curl.exe -i -G --data-urlencode "q=head" http://127.0.0.1:5050/search
curl.exe -i -G --data-urlencode "q=' OR 1=1 -- " http://127.0.0.1:5050/search
curl.exe -i -G --data-urlencode "q=' OR 1=1 -- " http://127.0.0.1:5051/search
curl.exe -i -G --data-urlencode "q=head" http://127.0.0.1:5051/search
```

Both modes find the headphones for `head`. The vulnerable injection reveals the hidden prototype; fixed mode returns HTTP 200 with `[]`. Compare [vulnerable SQL](../lab/vulnerable_sql.py) with [parameterized SQL](../lab/fixed_sql.py). The fixed query treats the payload as a value, preserving the public-product condition.

## Review the results

Read [findings and verification coverage](security-review.md), then compare the recorded [pipeline and ZAP evidence](../evidence/README.md). No scanner is executed by opening these documents.

Stop local servers with Ctrl+C. Never expose the vulnerable service publicly.
