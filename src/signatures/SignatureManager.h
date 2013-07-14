#ifndef FIRESQL_RULE_MANAGER_H
#define FIRESQL_RULE_MANAGER_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <vector>
#include "Signature.h"

template <class T>
class SingletonSignatureManager
{
public:
        template <typename... Args>

        static T* getInstance()
        {
                if(!signatureMngInstance_)
                {
                        signatureMngInstance_ = new T();
                }
                return signatureMngInstance_;
        }

        static void destroyInstance()
        {
                delete signatureMngInstance_;
                signatureMngInstance_ = nullptr;
        }

private:
        static T* signatureMngInstance_;
};

template <class T> T*  SingletonSignatureManager<T>::signatureMngInstance_ = nullptr;
class SignatureManager: public SingletonSignatureManager<SignatureManager>
{
public:

	int32_t getTotalSignatures() { return signatures_.size();}
	int32_t getTotalMatchingSignatures() { return total_matched_signatures_;}

	void evaluate(const std::string &query,bool *result); 

	void addSignature(const std::string expression);

	SignaturePtr getMachtedSignature();

	void statistics();
	friend class SingletonSignatureManager<SignatureManager>;
private:
	void addSignature(const SignaturePtr rule);
	SignaturePtr current_signature_;
	int32_t total_matched_signatures_;
	std::vector<SignaturePtr> signatures_;
};

#endif

