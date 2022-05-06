import logo from './logo.svg';
import './App.css';
import data from './OsDAhosts.json'
import "./Osdetec.css"
import $ from 'jquery'; 

function osdetect() {

 
         return (
    <div className="os">
        {data && data.map(post=>{
        return (
          
          <div  key={post.name} >
              <h1>Host address : {post.IP} </h1>
              <h2>Name : {post.name}</h2>
              <h3>Accuracy : {post.accuracy}</h3>
              <div>
                 { post.osclass.map(data =>{
                   return(
                   <div key={post.name} >
                    <h4>Type: {data.type}</h4>
                    <h4>Vendor: {data.vendor}</h4>
                    <h4>Os family : {data.osfamily}</h4>
                    <h4> Osgen :{data.osgen}</h4>
                    <h4> Cpe :{data.cpe}</h4>
                <button id='script' name="scriptbutton" value=" Run Script" onclick="goPython()"> click to run the code </button>
                <div>
                <script src="http://code.jquery.com/jquery-3.3.1.min.js" integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=" crossorigin="anonymous"></script>

                <script>
                    function goPython(){
                        $.ajax({
                          url: "osdetec.py",
                        context: document.body
                        }).done(function() {
                        
                        })
                    }
                </script>
                </div>
                   </div>
                   )
                 }
                  )}
              </div>

              
          </div>
        )

        }
          )}
      </div>

  );  
}

export default osdetect;
