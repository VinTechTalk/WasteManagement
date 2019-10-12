
$(document).ready(function(){

    $('#divRegister').hide();
    $('#divImageSection').hide();
    $('#btnSubscribe').hide();

    // $('#btn-predict').click(function () {

        // Upload Preview
        function readURL(input) {
            if (input.files && input.files[0]) {
                var reader = new FileReader();
                reader.onload = function (e) {
                    $('#imagePreview').css('background-image', 'url(' + e.target.result + ')');
                    $('#imagePreview').hide();
                    $('#imagePreview').fadeIn(650);
                }
                reader.readAsDataURL(input.files[0]);
            }
        }
        $("#imageUpload").change(function () {
            $('.image-section').show();
            $('#btn-predict').show();
            $('#result').text('');
            $('#result').hide();
            readURL(this);
        });

    // });

$('#btnRegister').click(function(){
    $('#divRegister').show();
    $('#divLogin').hide();
$('.bgDull').show(); /*To hide all other content it will create a translucent layer*/
$('.popup').fadeIn(3000);    /*Will show with animation your popup window*/
});


	$('#btnRegister2').click(function () {

        var myObject = new Object();
        myObject.fullName = $('#txtFullName').val();
        myObject.email = $('#txtEmail').val();
        myObject.password = $('#txtRegisterPassword').val();

        var data = JSON.stringify(myObject);

        $.ajax({
            type: 'POST',
            data:JSON.stringify(myObject),
            url: '/register',
            contentType: 'applicaion/json',
            cache: false,
            async: true,
            success: function (data) {
              
            },
        });
    });	


    $('#btnSubscribe').click(function(){
        window.location.replace("http://localhost:5000/index/"); 
    })

    $('#btn-predict').click(function () {
        var form_data = new FormData($('#upload-file')[0]);

        // Show loading animation
        $(this).hide();
        $('.loader').show();

        // Make prediction by calling api /predict
        $.ajax({
            type: 'POST',
            url: '/predict',
            data: form_data,
            contentType: false,
            cache: false,
            processData: false,
            async: true,
            success: function (data) {
                // Get and display the result
                $('.loader').hide();
                $('#result').fadeIn(600);
                $('#result').text(' Result:  ' + data);
                
                if(data == "Please subscribe to use the service")
                {
                    $('#btnSubscribe').show();    
                }
                else
                {
                    $('#lblResult').text(data);
                }
                console.log(data);
            },
        });
    });
	
})