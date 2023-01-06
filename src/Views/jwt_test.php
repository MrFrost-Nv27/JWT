<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>JWT Testing</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
</head>

<body class="bg-primary">
    <div class="container">
        <div class="row mt-4">
            <div class="col">
                <div class="card text-center">
                    <div class="card-header">
                        JWT Test
                    </div>
                    <div class="card-body">
                        <h5 class="card-title">Test your JSON Web Token here!</h5>
                        <form method="post" class="my-4">
                            <div class="form-floating">
                                <textarea class="form-control" placeholder="Drop your token here" name="token"
                                    style="height: 100px"></textarea>
                                <label for="floatingTextarea2">Token</label>
                            </div>
                            <div class="col-12 mt-4">
                                <button class="btn btn-primary" type="submit">Check</button>
                            </div>
                        </form>
                    </div>
                    <div class="card-footer text-muted">
                        MrFrost JWT Auth
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous">
    </script>
</body>

</html>