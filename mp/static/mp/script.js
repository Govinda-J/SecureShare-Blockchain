
function toggleForm(){
    var name = document.querySelector("#name")
    var email = document.querySelector("#email")
    var department = document.querySelector("#department")
    var subscription = document.querySelector("#subscription")

    var head = document.querySelector("form h2")
    var button = document.querySelector("form button")
    var para = document.querySelector(".toggle")
    if(head.textContent === "Login"){
        name.style.display = "initial";
        email.style.display = "initial";
        department.style.display = "initial";
        subscription.style.display = "initial";
        head.textContent = "Register";
        button.textContent = "Register";
        para.innerHTML = `Already have an account? <a onclick="toggleForm()">Login</a>`;
    }
    else{
        name.style.display = "none";
        email.style.display = "none";
        department.style.display = "none";
        subscription.style.display = "none";
        head.textContent = "Login";
        button.textContent = "Login";
        para.innerHTML = `Don't have an account? <a onclick="toggleForm()">Register</a>`;
    }
}

function goToCard(number) {
    var offset = (number - 1) * 100;
    const main = document.getElementById("main");
    main.style.transform = `translateX(-${offset}vw)`;
    main.style.transition = "all ease 1.5s";
}


button.addEventListener("click",function(){
    goToCard(2);
})

var upload = document.querySelector("#data-owner #upload");
upload.addEventListener("click",function(){
    var dataOwner = document.getElementById('data-owner');
    dataOwner.style.display = "none";
    var uploadFile = document.getElementById('upload-file');
    uploadFile.style.visibility = "visible";
})


function radioConfig(){
    if(document.getElementById("owner").checked){        
        var card = document.getElementById('card4');
        card.style.display = "none";
        goToCard(3);
    }
    else if(document.getElementById("user").checked){
        goToCard(4)
    }
    
}

var fileName = document.querySelector("#upload-file input");
console.log(fileName.textContent);