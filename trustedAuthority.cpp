#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <fstream>
#include <unistd.h>
#include <unordered_map>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

string ReadFile(string);
void WriteFile(string, string);
void Register(OpenABECryptoContext &cpabe);
void PrintList();
void PrintMenu();
unordered_map<string, string> userList;


int main(int argc, char **argv) {

  cout<<"		#################################################"<<endl;
  cout<<"		# ......... Authority for OABE system ......... #"<< endl;
  cout<<"		# .............. Generating key ............... #" <<endl;
  cout<<"		#################################################"<<endl<<endl;
  
  cout<<"[*] Initializing system: ";

  InitializeOpenABE();
  OpenABECryptoContext cpabe("CP-ABE");
  cpabe.generateParams();
  // userList["20521168"] = "pwn|re|crypto";
  // userList["20521194"] = "web|forensic|misc";
  // sleep(2);// seconds
  cout<<"DONE"<<endl;
  // ***********************************************
  cout<<"[*] Publishing Master Public Key: ";
  string mpk;
  cpabe.exportPublicParams(mpk);
  
  WriteFile("mpk.txt",mpk);
  // sleep(2);
  cout<<"DONE"<<endl;
  // sleep(2);
  
  cout<<"[*] Users can import the Master Public Key by reading the file \"ABE_MPK\""<<endl<<endl;
  // ***********************************************
  
  
while (1)
{
string option = "";
while(1)
{	
  PrintMenu();
  cout<<"> ";
  cin>>option;
  if (option == "-1")
  {
    cout<<"\nExiting ....."<<endl;
  ShutdownOpenABE();
  return 0; 	  	
  }
  if(option == "1")
  {
    Register(cpabe);
  }
  
  else if(option == "2")
  {
    PrintList();
  }
  
  else
  {
    cout<<"\n Invalid command ..... "<<endl;
  }
  
  option.clear();  
}
}
cout<<"Exiting ....."<<endl;


ShutdownOpenABE();

return 0;
}
string ReadFile(string filename)
{
ifstream myreadfile(filename);
stringstream buffer;
buffer << myreadfile.rdbuf();

string content;	

content = buffer.str();
  
    // Close the file
    
myreadfile.close();

return content;
}
void WriteFile(string filename, string content)
{

ofstream file_to_write;
file_to_write.open (filename);
file_to_write << content;
file_to_write.close();  

}

void Register(OpenABECryptoContext &cpabe)
{
cout<<"\n[*] User id\n\n> ";
string uid;
string attr;
cin >> uid;

string keyid = uid +".key" ;
if (userList.find(uid) == userList.end())
{
cout<< "\n[*] User " + uid + " attributes: ";  
cin>>attr;
userList.insert(make_pair(uid, attr));

}
else // already exsisted
{
cout<<"\nUser " + uid + " already exsists, update attributes ? (YES/NO)\n> ";
string update;
cin>>update;
transform(update.begin(), update.end(), update.begin(), ::tolower); 
if (update == "yes")
{
cout<< "\n[*] User " + uid + " attributes: ";  
cin>>attr;
userList[uid] = attr;
}

else // update == "no"
{
  return;
}
}
cout<<"\n[*] Generating key for user " + uid + ": ";

// sleep(2);
cpabe.keygen(attr, keyid); // cpabe.keygen(attrlist,keyid);
string tmp;
cpabe.exportUserKey(keyid, tmp);
WriteFile(keyid, tmp); 
cout<<"DONE"<<endl;
}
void PrintList()
{
  unordered_map<string, string>:: iterator itr;
  cout << "\n[*] All Users: \n";
  int count = 1;
  for (itr = userList.begin(); itr != userList.end(); itr++)
  {
  cout<<"\t"<<setw(3)<<count<<". ";
  cout << setw(10) << left <<itr->first << setw(30) << right <<itr->second << endl;
  count++;
  }
  cout<<endl;
}
void PrintMenu()
{ 
  cout<<"\n			********* COMMANDS ************\n";
  cout<<"			*      1. Register new user    *\n";
  cout<<"			*      2. Print user list      *\n";
  cout<<"			*     -1. Exit                 *\n";
  cout<<"			********************************\n\n";
}