<?php
include_once "includes/define.php";

if(isset($_POST['email']) && isset($_POST['name']) && isset($_POST['message'])) {
    $email = $_POST['email'];
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);

    $name = $_POST['name'];
    $name = filter_var($name, FILTER_SANITIZE_STRING);

    $message = $_POST['message'];
    $message = filter_var($message, FILTER_SANITIZE_STRING);
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $sql = "INSERT INTO contact_us (name, email, message) VALUES ('" . $name . "', '" . $email . "', '" . $message . "')";
        error_log($sql);
        if ($conn->query($sql) !== true) {
            error_log("Error: " . $sql . " - " . $conn->error);
            $_SESSION['message'] = "An error occurred.";
        } else
            $_SESSION['message'] = "Thank you. We will contact you shortly.";

    } else
        $_SESSION['message'] = "Invalid email address";
}

include "includes/header.php";
?>

  <section class="mb-5">
    <div class="container">
      <div class="row">
        <div class="col-md-6 mb-5">
          <h1 class="display-4">Contact Us</h1>
          <p class="lead text-secondary"></p>
        </div>
      </div>
    </div>
  </section>
  

  <section class="probootstrap-services">
    <div class="container">
      <div class="row no-gutters">
        <div class="col-md-3 pb-5 probootstrap-aside-stretch-left probootstrap-inside">
          <div class="mb-3 pt-5">
            <h2 class="h6">Contact</h2>
            <ul class="list-unstyled probootstrap-light mb-4">
              <li class="active"><a href="#">Contact</a></li>
              <li><a href="#">More Link</a></li>
              <li><a href="#">Another Link</a></li>
            </ul>
          </div>
        </div>
        <div class="col-md-9 pl-md-5 pb-5 pl-0 probootstrap-inside">
          <h1 class="mt-4 mb-4">Get In Touch</h1>
          <div class="row">
            <div class="col-md-12">
              <form method="post" class="probootstrap-form">
                <div class="form-group">
                  <label for="name" class="sr-only">Name</label>
                  <input name="name" type="text" class="form-control" id="name" placeholder="Enter your name">
                </div>
                <div class="form-group">
                  <label for="email" class="sr-only">Email</label>
                  <input name="email" type="text" class="form-control" id="email" placeholder="Enter your email">
                </div>
                <div class="form-group">
                  <label for="message" class="sr-only">Message</label>
                  <textarea name="message" id="message" cols="30" rows="10" class="form-control" placeholder="Write your message"></textarea>
                </div>
                <div class="form-group">
                  <input type="submit" class="btn btn-primary" value="Send Message">
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
  


<?php
include "includes/footer.php";
?>