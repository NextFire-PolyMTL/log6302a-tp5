<!DOCTYPE html>
<html lang="en">
<head>
    <title>Bucks Care</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <link href="https://fonts.googleapis.com/css?family=Work+Sans" rel="stylesheet">

    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="stylesheet" href="css/open-iconic-bootstrap.min.css">

    <link rel="stylesheet" href="css/owl.carousel.min.css">
    <link rel="stylesheet" href="css/owl.theme.default.min.css">

    <link rel="stylesheet" href="css/icomoon.css">
    <link rel="stylesheet" href="css/flaticon.css">
    <link rel="stylesheet" href="css/animate.css">
    <link rel="stylesheet" href="css/bootstrap-datepicker.css">
    <link rel="stylesheet" href="css/style.css">

</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark probootstrap-navbar-dark">
    <div class="container">
        <!-- <a class="navbar-brand" href="index.php">Health</a> -->
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#probootstrap-nav" aria-controls="probootstrap-nav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse" id="probootstrap-nav">
            <ul class="navbar-nav mr-auto">
                <?php
                foreach ($links as $key => $value) {
                    $classes = "nav-item";
                    if($_SERVER['REQUEST_URI'] == "/".$key)
                        $classes .= " active";
                    echo '<li class="'.$classes.'"><a href="/'.$key.'" class="nav-link pl-0">'.$value.'</a></li>';
                }

                ?>
            </ul>
            <!-- <div class="ml-auto">
                <form action="#" method="get" class="probootstrap-search-form mb-sm-0 mb-3">
                    <div class="form-group">
                        <button class="icon submit"><span class="icon-magnifying-glass"></span></button>
                        <input type="text" class="form-control" placeholder="Search">
                    </div>
                </form>
            </div>-->
        </div>
    </div>
</nav>
<!-- END nav -->
<header role="banner" class="probootstrap-header py-5">
    <div class="container">
        <div class="row">
            <div class="col-md-3 mb-4">
                <a href="index.php" class="mr-auto"><img src="images/logo.png" width="240" class="hires"></a>
            </div>
            <div class="col-md-9">
                <div class="float-md-right float-none">
                    <div class="probootstrap-contact-phone d-flex align-items-top mb-3 float-left">
                        <span class="icon mr-2"><i class="icon-phone"></i></span>
                        <span class="probootstrap-text"> +900 123 456 7 <small class="d-block"><a href="/index.php#appointment" class="arrow-link">Appointment <i class="icon-chevron-right"></i></a></small></span>
                    </div>
                </div>
            </div>
        </div>
    </div>
</header>