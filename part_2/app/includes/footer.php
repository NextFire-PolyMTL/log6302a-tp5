<!--<section class="probootstrap-subscribe">
    <div class="container">
        <div class="row mb-5">
            <div class="col-md-12">
                <h2 class="h1 text-white">Subscribe Newsletter</h2>
                <p class="lead text-white">Far far away, behind the word mountains, far from the countries Vokalia.</p>
            </div>
        </div>
        <form action="#" method="post">
            <div class="row">
                <div class="col-md-4">
                    <input type="text" class="form-control" placeholder="Name">
                </div>
                <div class="col-md-4 mb-md-0 mb-3">
                    <input type="text" class="form-control" placeholder="Email">
                </div>
                <div class="col-md-4">
                    <input type="submit" value="Subscribe" class="btn btn-primary btn-block">
                </div>

            </div>
        </form>
    </div>
</section> -->

<?php
require_once "includes/define.php";

if(isset($_POST['news_email']) ) {
    $email = $_POST['news_email'];
    $mail = filter_var($email, FILTER_SANITIZE_EMAIL);
    $sql = "SELECT * FROM newsletter WHERE email='";
    $sql = $sql . $email. "'";

    error_log($sql);
    $result = $conn->query($sql);

    if($result === false)
        echo $sql . " _ " . $conn->error;
    else {
        if ($result->num_rows > 0)
            $_SESSION['message'] = "You are already registered in our list as : " . $result->fetch_assoc()['email'];
        else {
            $email = $_POST['news_email'];
            $email = filter_var($email, FILTER_SANITIZE_EMAIL);
            if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $sql = "INSERT INTO newsletter (email) VALUES ('" . $email . "')";
                if ($conn->query($sql) !== true) {
                    error_log("Error: " . $sql . " - " . $conn->error);
                    $_SESSION['message'] = "An error occurred.";
                } else
                    $_SESSION['message'] = "Thank you. You are registered in the list.";
            } else
                $_SESSION['message'] = "Invalid email address";
        }
    }
}

?>

<footer class="probootstrap-footer">
    <div class="container">
        <div class="row mb-5">
            <div class="col-md-3">
                <h3 class="heading">Latest Blog</h3>
                <ul class="list-unstyled probootstrap-footer-recent-post">
                    <li>
                        <a href="#"><span class="date">November 15, 2017</span> The practice of medicine is a lot like parenting </a>
                    </li>
                    <li>
                        <a href="#"><span class="date">November 15, 2017</span>Physicians: Want to overcome burnout? Start studying business. </a>
                    </li>
                </ul>
            </div>
            <div class="col-md-3">
                <h3 class="heading">Head Office</h3>
                <p class="mb-5">98 West 21th Street, Suite 721 New York NY 10016</p>
                <h3 class="heading text-white">Open</h3>
                <p>
                    Mon-Fri 7:30-18:00 <br>
                    Sat 7:30-18:00 <br>
                    Sun 7:30-18:00
                </p>
            </div>
            <div class="col-md-3">
                <h3 class="heading">Quick Links</h3>
                <ul class="list-unstyled probootstrap-footer-links">
                    <?php
                    foreach ($links as $key => $value) {
                        echo '<li><a href="/'.$key.'">'.$value.'</a></li>';
                    }
                    ?>
                </ul>
            </div>
            <div class="col-md-3">
                <h3 class="heading">Follow us</h3>
                <ul class="probootstrap-footer-social">
                    <li><a href="#"><span class="icon-twitter"></span></a></li>
                    <li><a href="#"><span class="icon-facebook"></span></a></li>
                    <li><a href="#"><span class="icon-linkedin"></span></a></li>
                </ul>
            </div>
            <div class="col-md-5">
                <h3 class="heading">Subscribe Newsletter</h3>
                <form method="post">
                    <div class="row">
                        <div class="col-md-6">
                            <input name="news_email" type="text" class="form-control" placeholder="Email">
                        </div>
                        <div class="col-md-6">
                            <input type="submit" value="Subscribe" class="btn btn-primary btn-sm">
                        </div>
                    </div>
                </form>
            </div>
        </div>
        <!-- END row -->
        <div class="row probootstrap-copyright">
            <div class="col-md-12">
                <p><small>
                        &copy; 2017 <a href="https://uicookies.com/" target="_blank">uiCookies Health</a>. All Rights Reserved. Designed &amp; Developed by <a href="https://uicookies.com/" target="_blank">uicookies.com</a> <br/>
                        &copy; 2022 sketchy backend developed by <a href="mailto:julien.cassagne@polymtl.ca" target="_blank">Julien Cassagne</a> for LOG6302A - lab group x<br/>
                        Demo Images <a href="https://pexels.com/">Pexels</a>
                    </small></p>
            </div>
        </div>
    </div>
</footer>

<!-- loader -->
<div id="probootstrap-loader" class="show fullscreen"><svg class="circular" width="48px" height="48px"><circle class="path-bg" cx="24" cy="24" r="22" fill="none" stroke-width="4" stroke="#eeeeee"/><circle class="path" cx="24" cy="24" r="22" fill="none" stroke-width="4" stroke-miterlimit="10" stroke="#32609e"/></svg></div>

<!-- message -->
<div id="modal_message" class="modal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Message</h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <p><?php echo $_SESSION['message']; ?></p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<script src="js/jquery-3.2.1.min.js"></script>
<script src="js/popper.min.js"></script>
<script src="js/bootstrap.min.js"></script>
<script src="js/owl.carousel.min.js"></script>
<script src="js/jquery.waypoints.min.js"></script>
<script src="js/bootstrap-datepicker.js"></script>
<script src="js/jquery.animateNumber.min.js"></script>

<script src="js/main.js"></script>

<?php

if(isset($_SESSION['message'])) {
    echo '<script type="application/javascript"> $( document ).ready(function() { $("#modal_message").modal("show"); }); </script>';
    unset($_SESSION['message']);
}

?>
</body>
</html>