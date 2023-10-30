#include<bits/stdc++.h>
#include<unistd.h>
using namespace std;
#define int long long
using ii=pair<int,int>;   
#define F first
#define S second

//function for parsing the given input 
void split(string s,vector<string> &v){
	stringstream ss(s);
	string word;
	while(ss>>word){
		v.push_back(word);
	}
}


int n; // Number of routers

// struct for each router
struct Router {
	string name;
    int id;
    vector<int> routing_table;

    Router(int d,string s){
    	id=d;
    	name=s;
    	routing_table=vector<int>(n+1,1e9);
    	routing_table[d]=0;
    }
};

vector<string> inputs; //vector for storing inputs
map<string,Router*> routers; //map for accessing each routers struct by routers name 
vector<vector<ii>> network; //storing the given network
vector<queue<pair<vector<int>,int>>> communication_queue; //queue for communication for each router
vector<string> router_names; //names of routers in the given input
mutex mtx; //mutex variable for printing the table
vector<mutex> communication_queue_mutex; // mutex variables for communication queues


// function to check whether the given graph is connected or not
bool is_not_connected(){
	int comp=0;
	vector<int> vis(n+1,0);
	for(int i=1;i<=n;i++){
		if(!vis[i]){
			comp+=1;
			if(comp>1) return true;
			queue<int> q;q.push(i);
			while(!q.empty()){
				int f = q.front();q.pop();
				vis[f]=1;
				for(auto v : network[f]){
					if(!vis[v.F]){
						q.push(v.F);
					}
				}
			}
		}
	}
	return false;
}

//function to display the table of each router
void display_table(vector<int>&old_table,vector<int>new_table,string router_name,int cnt){
	
	
	int numRows = n;
    	int numColumns = 2;
    	int columnWidth = 18;
    	int ncolumnWidth = 16;
    
	mtx.lock();
	cout<<endl;
	cout<<"--------------------Router "<<router_name<<" Iteration:"<<cnt<<" --------------------"<<endl;

    // Print the top border
    cout<<setfill('-') << left <<setw(columnWidth)<<"+";
    cout<<setfill('-') << left <<setw(columnWidth)<<"+";
    cout<<"+"<<endl;
    cout<<setfill(' ');

    // Header row
    cout << "| " << left << setw(ncolumnWidth) << "Router_name" << "| " << left << setw(ncolumnWidth) << router_name << "|" << endl;

    // Separator row
   cout<<setfill('-') << left <<setw(columnWidth)<<"+";
    cout<<setfill('-') << left <<setw(columnWidth)<<"+";
    cout<<"+"<<endl;
    cout<<setfill(' ');

    // Data rows
    for (int i = 1; i <= numRows; i++) {
    	if(old_table[i]!=new_table[i])
    	{
    		string temp = to_string(new_table[i])+"*";
        	cout << "| " << left << setw(ncolumnWidth) << router_names[i-1] << "| " << left << setw(ncolumnWidth) << temp << "|" << endl;
        }
        else
        {
        	cout << "| " << left << setw(ncolumnWidth) << router_names[i-1] << "| " << left << setw(ncolumnWidth) << new_table[i] << "|" << endl;
        }
    }

    // Print the bottom border
   cout<<setfill('-') << left <<setw(columnWidth)<<"+";
    cout<<setfill('-') << left <<setw(columnWidth)<<"+";
    cout<<"+"<<endl;
    cout<<setfill(' ');

    mtx.unlock();
}


void routing_instance(string arg){
	int cnt=1;
	while(true){
		string router_name = arg;
		int router_id  = routers[router_name]->id;
		vector<int> table = routers[router_name]->routing_table;
		map<int,int> costs;
		for(auto v:network[router_id]){
			costs[v.F]=v.S;
			communication_queue_mutex[v.F].lock();
			communication_queue[v.F].push({table,router_id});
			communication_queue_mutex[v.F].unlock();
		}
		while(communication_queue[router_id].size()!=network[router_id].size()){sleep(1);}
		while(!communication_queue[router_id].empty()){
			pair<vector<int>,int> temp=communication_queue[router_id].front();communication_queue[router_id].pop();
			for(int i=1;i<=n;i++){
				table[i]=min(table[i],costs[temp.S]+(temp.F)[i]);
			}
		}
		display_table(routers[router_name]->routing_table,table,arg,cnt);
		routers[router_name]->routing_table = table;
		sleep(2);
		cnt++;
	}
}



void solve(){
	n=stoi(inputs[0]);
	network=vector<vector<ii>>(n+1);
	communication_queue=vector<queue<pair<vector<int>,int>>>(n+1);
	communication_queue_mutex=vector<mutex>(n+1);
	routers.clear();
	router_names.clear();

	split(inputs[1],router_names);
	
	for(int i=1;i<=n;i++){
		routers[router_names[i-1]] = new Router(i,router_names[i-1]);
	}

	for(int i=2;i<inputs.size();i++){
		string temp=inputs[i];
		if(temp=="END") break;

		vector<string> edge;
		split(inputs[i],edge);

		int cost = stoi(edge[2]);

		network[routers[edge[0]]->id].push_back({routers[edge[1]]->id,cost});
		network[routers[edge[1]]->id].push_back({routers[edge[0]]->id,cost});

	}

	if(is_not_connected()){
		cout<<"Given network is not connected"<<endl;
		return;
	}

	thread th[n+1];

	for(int i=1;i<=n;i++){
		th[i]=thread(routing_instance,router_names[i-1]);
	}

	for(int i=1;i<n;i++){
		th[i].join();
	}

}


signed main()
{
    fstream my_file;
    my_file.open("topology.txt",ios::in);
    inputs.clear();
    if(!my_file){
    	cout<<"No such file"<<endl;
    	return 0;
    }
    else{
    	string s;
    	while(getline(my_file,s)){
    		inputs.push_back(s);
    	}
    }
    solve();
}
