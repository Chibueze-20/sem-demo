mode = ''
table_show=false
Report = ''
selected = ''
data = []
fields=[]
tbody = []
pagesize =20,
pagenum = 1

function report(report,sender){
    if (!table_show) {
        document.getElementById("placeholder").innerHTML = "LOADING DATA"        
    }

    mode = "report"
    obj = $("#list a.report.active")
    if (obj.length==1){
        obj[0].classList.remove('active')
    }
    sender.classList.add('active')
    Report = report
    request('report',report)
    if (!table_show) {
        table_show=true
        document.getElementById("placeholder").style.display='none'
        document.getElementById("d_table").style.display='table'
        document.getElementById('table_wrap').style.display="block"
    }
    path = "/"+mode+"/save/"+Report
    $("#download").attr("href",path)

}

function Getevent(report){
    if (!table_show) {
        document.getElementById("placeholder").innerHTML = "LOADING DATA"        
    }
    mode = 'event'
    Report = report
    obj = $("#list a.report.active")
    if (obj.length==1){
        obj[0].classList.remove('active')
    }
    request('event',report)
    if (!table_show) {
        table_show=true
        document.getElementById("placeholder").style.display='none'
        document.getElementById("d_table").style.display='table'
        document.getElementById('table_wrap').style.display="block"
    }
    path = "/"+mode+"/save/"+Report
    $("#download").attr("href",path)
}
function request(path,param){
    $.ajax({
        url:"/"+path+"/"+param,

        success:function(result){
            
                papa = Papa.parse(
                    result,
                    {
                        header:true,
                        skipEmptyLines: true,
                    }
                    )
                // console.log(papa.data)
                fields = papa.meta.fields
                data = papa.data
                fillTable(fields,table_rows(show(pagesize,pagenum,data)))
        }
    })
}
function Pagesize(num,sender){
    obj = $("ul a.pg.active")
    if (obj.length==1){
        obj[0].classList.remove('active')
    }
    sender.classList.add('active')
    pagesize = num
    fillTable(fields,table_rows(show(pagesize,pagenum,data)))
}
function nextpage(){
    pagenum +=1
    fillTable(fields,table_rows(show(pagesize,pagenum,data)))
}
function prevpage(){
    pagenum -=1
    fillTable(fields,table_rows(show(pagesize,pagenum,data)))
}

function table_rows(json_data){
    arr =[]
    for (let index = 0; index < json_data.length; index++) {
        const tr = document.createElement('tr')
        const element = json_data[index];
        const fields = Object.keys(element)
        fields.forEach(elem=>{
            td = document.createElement('td')
            td.innerHTML=element[elem]
            tr.appendChild(td)
    })
    arr.push(tr)
}
    return arr
}
function show(){
    maxPages = Math.ceil(data.length/pagesize)
     if (pagenum>maxPages) {
         alert("Last page of data, showing first page")
         pagenum=1
     }else if(pagenum<1){
         alert("First page of data")
         pagenum=1
     }
     startIndex = (pagenum - 1) * pagesize;
     endIndex = Math.min(startIndex + pagesize - 1, data.length - 1);
     return data.slice(startIndex,endIndex+1)
}

function selectfield(event){
    selected = event.currentTarget.innerHTML
    obj = $("#d_table th.th-sm.selected")
    if (obj.length==1){
        obj[0].classList.remove('selected')
    }
    event.currentTarget.classList.add('selected')
}

function fillTable(fields,dtbody){
    thead = document.createElement('thead')
    thead.classList.add('thead-light')
    tbody = buildBody(dtbody)
    tfoot = document.createElement('tfoot')
    fields.forEach(element => {
        hth = document.createElement('th')
        hth.addEventListener('click', selectfield, {once : false});
        fth = document.createElement('th')
        hth.classList.add('th-sm')
        hth.innerHTML = element
        fth.innerHTML = element
        thead.appendChild(hth)
        tfoot.appendChild(fth)
    });
    
    table = document.getElementById('d_table')
    table.innerHTML=""
    table.appendChild(thead)
    table.appendChild(tbody)
    table.appendChild(tfoot)  
}
function buildBody(trdata){
    tbody = document.createElement('tbody')
    trdata.forEach(element => {
        tbody.appendChild(element)
    });
    return tbody;
}

