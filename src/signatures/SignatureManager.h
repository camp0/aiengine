#ifndef _SignatureManager_H_
#define _SignatureManager_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <vector>
#include "Signature.h"

class SignatureManager
{
public:
        explicit SignatureManager():
                total_matched_signatures_(0),
		current_signature_(nullptr)
        {
        }

        virtual ~SignatureManager()=default;

	int32_t getTotalSignatures() { return signatures_.size();}
	int32_t getTotalMatchingSignatures() { return total_matched_signatures_;}

	void evaluate(const unsigned char *payload,bool *result); 

	void addSignature(const std::string expression);
	void addSignature(SignaturePtr sig);
	void addSignature(Signature& sig);

	SignaturePtr getMachtedSignature();

	friend std::ostream& operator<< (std::ostream& out, const SignatureManager& sig);
//	std::string toString() { std::ostringstream s; s << this; return s.str();}; // Wrapper for python 

private:
	SignaturePtr current_signature_;
	int32_t total_matched_signatures_;
	std::vector<SignaturePtr> signatures_;
};

typedef std::shared_ptr<SignatureManager> SignatureManagerPtr;
typedef std::weak_ptr<SignatureManager> SignatureManagerPtrWeak;

#endif // _SignatureManager_H_

