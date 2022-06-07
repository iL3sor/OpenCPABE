#include <iostream>
	#include <string>
	#include <cassert>
	#include <openabe/openabe.h>
	#include <openabe/zsymcrypto.h>
	#include <fstream>
	#include <bits/stdc++.h>

	using namespace std;
	using namespace oabe;
	using namespace oabe::crypto;

	map<string, long unsigned int> account;
	hash<string> hashFunc;

	bool check(string username, string pass){
	  if(account[username] == hashFunc(pass)){
	    return true;
	  }
	  return false;
	}

	void encrypt(OpenABECryptoContext &cpabe){
	  string ct, pt1;
	  string plainFileName;
	  cout<<"[[ Plaintext file name  ]]  ";
	  cin.ignore(); 
	  getline(cin,plainFileName);
	  cout<<endl;
	  ifstream plain(plainFileName);
	  ostringstream ssplain;
	  ssplain << plain.rdbuf(); // reading data
	  pt1= ssplain.str();

	  string mpk;
	  ifstream mpkey("mpk.txt");
	  ostringstream ss;
	  ss << mpkey.rdbuf(); // reading data
	  mpk = ss.str();

	  cpabe.importPublicParams(mpk);
	  string attr ;
	  cout<<"[[ Enter policy ]]  ";
	  getline(cin, attr);
	  cout<<endl;
	  cpabe.encrypt(attr, pt1, ct);
	  cout<<"[[ Ciphertext file name ]] ";
	  string ciphertextFileName;
	  getline(cin, ciphertextFileName);
	  cout<<endl;
	  std::ofstream cipher(ciphertextFileName);
	  cipher << ct;
	  cipher.close();
	  cout<<"******** Encrypt successfully ********"<<endl;
	  cout<<endl;
	}
	void decrypt(OpenABECryptoContext &cpabe, string username){
	    cout<<"[[*** File name to decrypt ***]]:  ";
	    string filename;
	    cin.ignore();
	    getline(cin, filename);
	    string ct, pt2;
	    ifstream cipher(filename);
	    ostringstream ciph;
	    ciph << cipher.rdbuf(); // reading data
	    ct = ciph.str();

	    string mpk;
	    ifstream mpkey("mpk.txt");
	    ostringstream ss;
	    ss << mpkey.rdbuf(); // reading data
	    mpk = ss.str();

	    cpabe.importPublicParams(mpk);

	    string key0, keyID;
	    ifstream key(username+".key");
	    ostringstream ss2;
	    ss2 << key.rdbuf(); // reading data
	    key0 = ss2.str();
	    cpabe.importUserKey(keyID, key0);

	    cpabe.decrypt(keyID, ct, pt2);
	    cout<<endl;
	    if(pt2!=""){
	      cout << "[[Recovered message]] =====>    " << pt2 << endl;
	    }
	    else
	       {
		 cout<<"[[ You do not have permission to access this document !!! ]]"<<endl;
	       }
	    cout<<endl;
	}
	void login(string &username, string &pass){
	    cout<<"         [ --- Sign in --- ]"<<endl;
	    cout<<"   [Username]:  "; cin>> username;
	    cout<<"   [Password]:  "; cin>>pass;
	    cout<<endl;
	}

	int main(int argc, char **argv){
	    InitializeOpenABE();
	    OpenABECryptoContext cpabe("CP-ABE");
	    
	    account["owner"] = hashFunc("owner");
	    account["user"] = hashFunc("user");
	    account["attacker"] = hashFunc("attacker");
	    string username, pass;
	    int option;
	    login(username, pass);
	    if(check(username, pass)){
	      cout<<"******* Sign in successfully *******"<<endl;
	    }
	    else{
	      cout<<"Sign in failed!!!"<<endl;
	      ShutdownOpenABE();
	      return 0;
	    }
	    while(1){
	      cout<<"[[Enter your option: 1. Encrypt   2.Decrypt  3.Exit]] ";
	      cin>>option;
	      if(option==1){
		  encrypt(cpabe);
	      }
	      else if(option ==2 ){
		  decrypt(cpabe, username);
	      }
	      else
		  break;
	    }
	    ShutdownOpenABE();
	    return 0;
	}