<?php
require_once "includes/define.php";

if(isset($_POST['email']) && isset($_POST['name']) && isset($_POST['date']) && isset($_POST['message'])) {
    $email = $_POST['email'];
    $name = $_POST['name'];
    $date = $_POST['date'];
    $message = $_POST['message'];

    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $name = filter_var($name, FILTER_SANITIZE_STRING);
        $date = filter_var($date, FILTER_SANITIZE_STRING);
        $message = filter_var($message, FILTER_SANITIZE_STRING);
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);
        $sql = "INSERT INTO appointments (name, email, date, message) VALUES ('" . $name . "', '" . $email . "', '" . $date . "', '" . $message . "')";
        error_log($sql);
        if ($conn->query($sql) !== true) {
            error_log("Error: " . $sql . " - " . $conn->error);
            $_SESSION['message'] = "An error occurred.";
        } else
            $_SESSION['message'] = "Thank you. Your appointment is booked.";

    } else
        $_SESSION['message'] = "Invalid email address";
}


$n_app = 0;
$sql = "SELECT COUNT(*) as c FROM appointments";
$result = $conn->query($sql);
if ($result->num_rows != 1)
    echo $conn->error;
else
    $n_app = $result->fetch_assoc()['c'];

$n_patients = 0;
$sql = "SELECT COUNT(*) as c FROM patients";
$result = $conn->query($sql);
if ($result->num_rows != 1)
    echo $conn->error;
else
    $n_patients = $result->fetch_assoc()['c'];


include "includes/header.php";
?>

  <section class="mb-5">
    <div class="container">
      <div class="row">
        <div class="col-md-6 mb-5">
          <h1 class="display-4">The Future Of Medical services</h1>
          <p class="lead text-secondary">A healthcare that fits your life</p>
        </div>
      </div>
    </div>
  </section>
  
  <section class="probootstrap-features-1">
    <div class="container">
      <div class="row">
        <div class="col-md probootstrap-feature-item" style="background-image: url(images/img_1.jpg);">
          <div class="probootstrap-feature-item-text">
            <span class="icon"><i class="flaticon-first-aid-kit display-4"></i></span>
            <h2>Pediatric <span>Therapy</span></h2>
          </div>
        </div> 
        <div class="col-md probootstrap-opening">
          <h2 class="text-uppercase mb-3">Opening Hour <span>Medical Center</span></h2>
          <ul class="list-unstyled probootstrap-schedule">
            <li>Mon-Fri <span>5:00-17:00</span></li>
            <li>Sat <span>6:30-17:00</span></li>
            <li>Sun <span>6:30-17:00</span></li>
          </ul>
        </div> 
        <div class="col-md probootstrap-feature-item" style="background-image: url(images/img_2.jpg);">
          <div class="probootstrap-feature-item-text">
            <span class="icon"><i class="flaticon-gym-control-of-exercises-with-a-list-on-a-clipboard-and-heart-beats display-4"></i></span>
            
            <h2>Psychiatric <span>Therapy</span></h2>
          </div>
        </div> 
      </div>
    </div>
  </section>

  <section class="probootstrap-services">
    <div class="container">
      <div class="row no-gutters">
        <div class="col-md-3 probootstrap-aside-stretch-left">
          <div class="mb-3">
            <h2 class="h6">Departments</h2>
            <ul class="list-unstyled probootstrap-light mb-4">
              <li><a href="#">Urology</a></li>
              <li><a href="#">Pediatrics</a></li>
              <li><a href="#">Psychiatrics</a></li>
              <li><a href="#">Plastic Surgery</a></li>
              <li><a href="#">Neurosurgery</a></li>
            </ul>
            <p><a href="#" class="arrow-link text-white">More departments  <i class="icon-chevron-right"></i></a></p>
          </div>
        </div>
        <div class="col-md-9 pl-md-5 pl-0">
          <div class="row mb-5">
              
              <div class="col-lg-4 col-md-6">
                <div class="media d-block mb-4 text-left probootstrap-media">
                  <div class="probootstrap-icon mb-3"><span class="flaticon-price-tag display-4"></span></div>
                  <div class="media-body">
                    <h3 class="h5 mt-0 text-secondary">Medical Pricing</h3>
                    <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
                  </div>
                </div>
              </div>
              <div class="col-lg-4 col-md-6">
                <div class="media d-block mb-4 text-left probootstrap-media">
                  <div class="probootstrap-icon mb-3"><span class="flaticon-shield-with-cross display-4"></span></div>
                  <div class="media-body">
                    <h3 class="h5 mt-0 text-secondary">Quality &amp; Safety</h3>
                    <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
                  </div>
                </div>
              </div>
              <div class="col-lg-4 col-md-6">
                <div class="media d-block mb-4 text-left probootstrap-media">
                  <div class="probootstrap-icon mb-3"><span class="flaticon-first-aid-kit display-4"></span></div>
                  <div class="media-body">
                    <h3 class="h5 mt-0 text-secondary">Immidiate Service</h3>
                    <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
                  </div>
                </div>
              </div>

              <div class="col-lg-4 col-md-6">
                <div class="media d-block mb-4 text-left probootstrap-media">
                  <div class="probootstrap-icon mb-3"><span class="flaticon-microscope display-4"></span></div>
                  <div class="media-body">
                    <h3 class="h5 mt-0 text-secondary">Cutting-Edge Equipment</h3>
                    <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
                  </div>
                </div>
              </div>
              <div class="col-lg-4 col-md-6">
                <div class="media d-block mb-4 text-left probootstrap-media">
                  <div class="probootstrap-icon mb-3"><span class="flaticon-gym-control-of-exercises-with-a-list-on-a-clipboard-and-heart-beats display-4"></span></div>
                  <div class="media-body">
                    <h3 class="h5 mt-0 text-secondary">Personalized Treatment</h3>
                    <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
                  </div>
                </div>
              </div>
              <div class="col-lg-4 col-md-6">
                <div class="media d-block mb-4 text-left probootstrap-media">
                  <div class="probootstrap-icon mb-3"><span class="flaticon-doctor display-4"></span></div>
                  <div class="media-body">
                    <h3 class="h5 mt-0 text-secondary">Experience Physicians</h3>
                    <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
                  </div>
                </div>
              </div>
            </div>
        </div>
      </div>
    </div>
  </section>
  <section class="probootstrap-section overlay bg-image" style="background-image: url(images/bg_1.jpg)">
    <div class="container">
      <div class="row">
        <div class="col-md-12 text-center">
          <h2 class="text-white display-4">Specialists in Family  Healthcare</h2>
          <p class="text-white mb-5 lead">Far far away, behind the word mountains, far from the countries Vokalia.</p>
          <div class="row justify-content-center mb-5">
            <div class="col-md-4"><a href="/index.php#appointment" class="btn btn-secondary btn-block">Appointment <span class="icon-arrow-right"></span></a></div>
          </div>
        </div>
      </div>
    </div>
  </section>



  <section id="appointment" class="probootstrap-blog-appointment">
    <div class="container">
      <div class="row no-gutters">
        <div class="col-md-6 pr-md-5 pr-0 pt-md-5 pt-0 pb-md-5 pb-0">
          <h2 class="h1 mb-4 text-white">Recent Blog</h2>
          <ul class="probootstrap-blog-list list-unstyled">
            <li>
              <h2><span class="date">November 15, 2017</span><a href="#">The practice of medicine is a lot like parenting </a></h2>
            </li>
            <li>
              <h2><span class="date">November 15, 2017</span><a href="#">Physicians: Want to overcome burnout? Start studying business. </a></h2>
            </li>
            <li>
              <h2><span class="date">November 15, 2017</span><a href="#">Want a simple and easy-to-use EMR? Well, you can have it for free. </a></h2>
            </li>
          </ul>
          <p><a href="#" class="arrow-link">View All  <i class="icon-chevron-right"></i></a></p>
        </div>
        <div class="col-md-6 p-md-5 p-3 probootstrap-aside-stretch-right">
          <h2 class="h1 text-white">Make an Appointment</h2>
          <form method="post" class="probootstrap-form-appointment">
            <div class="form-group">
              <input name="name" type="text" class="form-control" placeholder="Your Name">
            </div>
            <div class="form-group">
              <input name="email" type="email" class="form-control" placeholder="Your Email">
            </div>
            <div class="form-group">
              <span class="icon"><i class="icon-calendar"></i></span>
              <input name="date" type="text" id="probootstrap-date" class="form-control" placeholder="Appointment Date">
            </div>
            <div class="form-group">
              <textarea name="message" class="form-control" id="" cols="30" rows="10" placeholder="Write your message"></textarea>
            </div>
            <div class="form-group">
              <input type="submit" value="Submit Form" class="btn btn-secondary">
            </div>
          </form>
        </div>
      </div>
    </div>
  </section>

  <section class="probootstrap-section">
    <div class="container">
      <div class="row">
        <div class="col-lg-4 col-md-6">
          <div class="media d-block mb-5 text-center probootstrap-media">
            <div class="probootstrap-icon mb-3"><span class="flaticon-price-tag display-4"></span></div>
            <div class="media-body">
              <h3 class="h5 mt-0 text-secondary">Medical Pricing</h3>
              <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
            </div>
          </div>
        </div>
        <div class="col-lg-4 col-md-6">
          <div class="media d-block mb-5 text-center probootstrap-media">
            <div class="probootstrap-icon mb-3"><span class="flaticon-shield-with-cross display-4"></span></div>
            <div class="media-body">
              <h3 class="h5 mt-0 text-secondary">Quality &amp; Safety</h3>
              <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
            </div>
          </div>
        </div>
        <div class="col-lg-4 col-md-6">
          <div class="media d-block mb-5 text-center probootstrap-media">
            <div class="probootstrap-icon mb-3"><span class="flaticon-microscope display-4"></span></div>
            <div class="media-body">
              <h3 class="h5 mt-0 text-secondary">Cutting-Edge Equipment</h3>
              <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
            </div>
          </div>
        </div>

        <div class="col-lg-4 col-md-6">
            <div class="media d-block mb-5 text-center probootstrap-media">
              <div class="probootstrap-icon mb-3"><span class="flaticon-microscope display-4"></span></div>
              <div class="media-body">
                <h3 class="h5 mt-0 text-secondary">Cutting-Edge Equipment</h3>
                <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
              </div>
            </div>
          </div>
          <div class="col-lg-4 col-md-6">
            <div class="media d-block mb-5 text-center probootstrap-media">
              <div class="probootstrap-icon mb-3"><span class="flaticon-gym-control-of-exercises-with-a-list-on-a-clipboard-and-heart-beats display-4"></span></div>
              <div class="media-body">
                <h3 class="h5 mt-0 text-secondary">Personalized Treatment</h3>
                <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
              </div>
            </div>
          </div>
          <div class="col-lg-4 col-md-6">
            <div class="media d-block mb-5 text-center probootstrap-media">
              <div class="probootstrap-icon mb-3"><span class="flaticon-doctor display-4"></span></div>
              <div class="media-body">
                <h3 class="h5 mt-0 text-secondary">Experience Physicians</h3>
                <p>Far far away, behind the word mountains, far from the countries Vokalia.</p>
              </div>
            </div>
          </div>

      </div>
     <!--  <div class="row">
         
      </div> -->
    </div>
  </section>

  <section class="probootstrap-section bg-light">
    <div class="container">
      <div class="row mb-5">
        <div class="col-md-12 text-center">
          <h2 class="h1">Our Doctors</h2>
          <p class="lead text-secondary">Your money, our passion.</p>
        </div>
      </div>
      <div class="row no-gutters">
        <div class="col-lg-3 col-md-3 col-sm-6 col-6 prbootstrap-team">
          <img src="images/person_1.jpg" alt="Free Template by uicookies.com" class="img-fluid">
          <div class="probootstrap-person-text">
            <span class="title">Medical Doctor</span>
            <span class="name">Dr. Abbey Smith</span>
          </div>
        </div>
        <div class="col-lg-3 col-md-3 col-sm-6 col-6 prbootstrap-team">
          <img src="images/person_2.jpg" alt="Free Template by uicookies.com" class="img-fluid">
          <div class="probootstrap-person-text">
            <span class="title">Medical Doctor</span>
            <span class="name">Dr. Ben Carpio</span>
          </div>
        </div>
        <div class="col-lg-3 col-md-3 col-sm-6 col-6 prbootstrap-team">
          <img src="images/person_3.jpg" alt="Free Template by uicookies.com" class="img-fluid">
          <div class="probootstrap-person-text">
            <span class="title">Medical Doctor</span>
            <span class="name">Dr. Louisa Westwood</span>
          </div>
        </div>
        <div class="col-lg-3 col-md-3 col-sm-6 col-6 prbootstrap-team">
          <img src="images/person_4.jpg" alt="Free Template by uicookies.com" class="img-fluid">
          <div class="probootstrap-person-text">
            <span class="title">Cardiac Surgeon</span>
            <span class="name">Dr. Mark Sebastian</span>
          </div>
        </div>
      </div>
    </div>
  </section>

  <section class="probootstrap-section" id="section-counter">
      <div class="container">
        <div class="row">
          <div class="col-md probootstrap-animate">
            <div class="probootstrap-counter text-center">
              <span class="probootstrap-number" data-number="22">0</span>
              <span class="probootstrap-label">Founders</span>
            </div>
          </div>
          <div class="col-md probootstrap-animate">
            <div class="probootstrap-counter text-center">
              <span class="probootstrap-number" data-number="182">0</span>
              <span class="probootstrap-label">Number of Staffs</span>
            </div>
          </div>
          <div class="col-md probootstrap-animate">
            <div class="probootstrap-counter text-center">
              <span class="probootstrap-number" data-number="<?php echo $n_patients; ?>">0</span>
              <span class="probootstrap-label">Happy Patients</span>
            </div>
          </div>    
          <div class="col-md probootstrap-animate">
            <div class="probootstrap-counter text-center">
              <span class="probootstrap-number" data-number="<?php echo $n_app; ?>">0</span>
              <span class="probootstrap-label">Appointments</span>
            </div>
          </div>    
        </div>
      </div>
      
    </section>




<?php
include "includes/footer.php";
?>